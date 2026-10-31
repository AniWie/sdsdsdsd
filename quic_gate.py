#!/usr/bin/env python3
"""
QUIC GOS gate server for WeiMianYe.

Accepts QUIC connections on UDP 25301/25302, completes TLS handshake,
reads the GOS login request, and responds with a crafted login response.

Replaces the passive quic_capture.py.
"""
import asyncio
import datetime
import logging
import os
import ssl
import struct
import sys
import time

from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import (
    QuicEvent,
    StreamDataReceived,
    ConnectionTerminated,
    HandshakeCompleted,
    StopSendingReceived,
    StreamReset,
    DatagramFrameReceived,
)
from aioquic.tls import SessionTicketFetcher

# Monkey-patch aioquic TLS to accept ANY ALPN the client sends.
# The game's GOS client (quic-go) requires ALPN negotiation. Without a
# matching protocol in EncryptedExtensions, the client aborts with TLS
# alert 120 (no_application_protocol), QUIC error 0x178 = 376.
#
# We patch Context._server_handle_hello to accept whatever ALPN the
# client offers, so the handshake completes.
import aioquic.tls as _tls_mod

# Patch negotiate() to return the first offered protocol
# when no match is found, instead of raising AlertHandshakeFailure.
# This lets the QUIC handshake complete regardless of what ALPN the
# game's GOS client requests.
_orig_negotiate = _tls_mod.negotiate

def _patched_negotiate(supported, offered, exc=None):
    result = _orig_negotiate(supported, offered, None)
    if result is not None:
        return result
    exc_msg = str(exc) if exc else ""
    if "ALPN" in exc_msg:
        if offered is not None and len(offered) > 0:
            log(f"ALPN: no match in {supported}, accepting client's {offered[0]}")
            return offered[0]
        # Client didn't send ALPN — skip it entirely
        log("ALPN: client sent no ALPN, skipping")
        return None
    if exc is not None:
        raise exc
    return None

_tls_mod.negotiate = _patched_negotiate

LOG_PATH = r"D:\Games\WeiMianYe\bypass\logs\quic_gate.log"
CERT_DIR = r"D:\Games\WeiMianYe\bypass\certs"

# ---------------------------------------------------------------------------
# MSG enum from Nezha/Protobuf/unrealmessage.js
# (recovered from the V8 code cache cbc/unrealmessage.min.cbc; the two values
#  below are pinned by observed wire bytes, not guessed)
#
# Declaration order in the enum, for reference:
#   MSG_NONE, UNREAL_MESSAGE, UNREAL_PAIRALIVE, GATE_TRANSFER, UNREAL_OPEN,
#   UNREAL_CLOSE, CONNECT_GATE, SHUTDOWN, RESTART_GS, ALLOC_GS, RESTART_BUS,
#   RESTART_GATE, BUS_USE_DEDICATED, SEQUENCE_MESSAGE, SHUTDOWN_ASK,
#   SHUTDOWN_CONFIRM, SHUTDOWN_DO, SHUTDOWN_CANCEL, REGISTER_WAITING,
#   RELIABLE_MESSAGE, RELIABLE_ACK, GATE_LOAD_PROBE, GATE_LOAD_PROBE_RESULT,
#   INTERNAL_LIMIT, CLI_ACCOUNT_LOGIN, CLI_ROLE_TELEPORT, CLI_QUEUE_INFO, ...
#
# Message names come in MsgFromUnreal*/MsgToUnreal* pairs that SHARE a msgID;
# direction is implied by who sends it.
# ---------------------------------------------------------------------------
MSG_UNREAL_OPEN = 0x65        # 101, observed: client -> gate, MsgFromUnrealOpen
MSG_HEART = 0x77              # 119, observed: heartbeat both ways
MSG_CLI_ACCOUNT_LOGIN = 1001  # 0x3E9, observed: client -> gate, C2GAccountLogin
MSG_CONNECT_GATE = 103  # 0x67, from unrealpb MsgID enum bytecode (f4 1c 0d 67):
                        # UNREAL_OPEN=101, UNREAL_CLOSE=102, CONNECT_GATE=103
                              # handler confirmed: RecvCliAccountLogin (MessageHandler.min.cbc)
CERT_FILE = os.path.join(CERT_DIR, "server.pem")
KEY_FILE = os.path.join(CERT_DIR, "server.key")

os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("quic_gate")

# Also log to file
fh = logging.FileHandler(LOG_PATH, mode="a", encoding="utf-8")
fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
logger.addHandler(fh)


def log(msg):
    line = f"[{datetime.datetime.now().isoformat(timespec='milliseconds')}] {msg}"
    print(line, flush=True)
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def hexdump(data, max_bytes=512):
    if not data:
        return "(empty)"
    trunc = data[:max_bytes]
    lines = []
    for i in range(0, len(trunc), 16):
        chunk = trunc[i:i+16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"  {i:04x}  {hex_part:<47}  {ascii_part}")
    if len(data) > max_bytes:
        lines.append(f"  ... ({len(data)} bytes total)")
    return "\n".join(lines)


class GOSGateProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._login_received = False
        self._stream_buffer = bytearray()
        self._ue_resp_count = 0        # v16: UE handshake responses sent —
                                       # each response must advance its own Seq
                                       # (the client's sliding window rejects
                                       # duplicate Seq after 2 entries)

    def quic_event_received(self, event: QuicEvent):
        if isinstance(event, HandshakeCompleted):
            log(f"HANDSHAKE COMPLETED alpn={event.alpn_protocol}")
            # Do NOT send server-initiated greeting.
            # Client opens its own stream and sends ping (119) or register (101).
            # Server-initiated messages (100, 119) cause "OnMessage NNN" errors.

        elif isinstance(event, StreamDataReceived):
            data = event.data
            log(f"STREAM {event.stream_id} end_stream={event.end_stream} len={len(data)}")
            log(f"STREAM DATA:\n{hexdump(data)}")

            # GOS packet format: <u16 BE total_len> <u16 BE msg_type> <u8 flags> <protobuf>
            # total_len = 2 (msg_type) + 1 (flags) + len(protobuf)
            # Full packet = 2 (total_len field) + total_len
            self._stream_buffer += data
            while len(self._stream_buffer) >= 5:
                total_len = struct.unpack_from(">H", self._stream_buffer, 0)[0]
                pkt_len = 2 + total_len
                if len(self._stream_buffer) < pkt_len:
                    break
                packet = self._stream_buffer[:pkt_len]
                self._stream_buffer = self._stream_buffer[pkt_len:]

                msg_type = struct.unpack_from(">H", packet, 2)[0]

                # ---- CONNECT_GATE PRE-SEND (msgID 103) ----
                # 23:06 run: 'ClientTravel nz.1-0' printed BEFORE 'RecvConnectGate
                # () 1:1' — our follow-up arrived too late to influence the URL.
                # With conn=0 (22:56) the handler passed the connection check but
                # travel still failed; with conn=1 the handler errors 'no
                # connection to gs 1:1' because only the gate link (node 1, conn 0)
                # exists. Proper server order: CONNECT_GATE first (registers the
                # DS connection), THEN the 1001 answer (login flow builds the
                # travel URL from the registered DS node/conn).
                if msg_type == MSG_CLI_ACCOUNT_LOGIN:
                    cg = self._build_connect_gate()
                    if cg:
                        log(f"SENDING CONNECT_GATE (pre) on STREAM {event.stream_id} len={len(cg)}")
                        log(f"CONNECT_GATE FRAME:\n{hexdump(cg)}")
                        self._quic.send_stream_data(event.stream_id, cg, end_stream=False)
                        self.transmit()

                response = self._build_response(packet)
                if response:
                    # Respond on the SAME stream_id (not a new one — prevents loop)
                    log(f"SENDING RESPONSE on SAME STREAM {event.stream_id} len={len(response)}")
                    log(f"RESPONSE:\n{hexdump(response)}")
                    self._quic.send_stream_data(event.stream_id, response, end_stream=False)
                    self.transmit()

        elif isinstance(event, DatagramFrameReceived):
            log(f"DATAGRAM len={len(event.data)}")
            log(f"DATAGRAM DATA:\n{hexdump(event.data)}")

        elif isinstance(event, ConnectionTerminated):
            log(f"CONNECTION TERMINATED: {event.error_code} {event.reason_phrase}")

        elif isinstance(event, StreamReset):
            log(f"STREAM RESET {event.stream_id}")

        elif isinstance(event, StopSendingReceived):
            log(f"STOP SENDING {event.stream_id}")

    def _build_response(self, request_data):
        """
        Build a GOS response with proper framing.

        GOS packet format: <u16 BE total_len> <u16 BE msg_type> <u8 flags> <protobuf>
        where total_len = 2 (msg_type) + 1 (flags) + len(protobuf)

        The u16 "msg_type" is the MSG enum from Nezha/Protobuf/unrealmessage.js
        (recovered from the V8 code cache cbc/unrealmessage.min.cbc). It is NOT
        a request/response pair: the SAME msgID is used in both directions and
        the direction is encoded in the message NAME, MsgFromUnreal* (client ->
        gate) vs MsgToUnreal* (gate -> client).

        Confirmed enum values from the observed wire bytes:
          119 (0x77) = heartbeat/ping, body PingBody{NeedReply}
          101 (0x65) = UNREAL_OPEN, body MsgFromUnrealOpen{Identity: string}

        Therefore 102 is UNREAL_CLOSE, not "cmdResponse". Replying 102 to an
        UNREAL_OPEN literally tells the client "close", which is exactly what
        it then did (~250ms later, ActiveClose) and why the client reported
        ERR_GOS_GATE_CLOSED [20047].

        Client sends:
          type=119: ping,      payload = <u8 flags> (empty protobuf)
          type=101: UNREAL_OPEN, payload = <u8 flags=0> <pb field1 = ":<pid>">

        We respond:
          type=119 -> type=119 (echo ping, unchanged - that already works)
          type=101 -> type=101 with MsgToUnrealOpen{TimeStampSec, ReconnectSec}
        """
        if len(request_data) < 5:
            log(f"TOO SHORT: {len(request_data)} bytes")
            return None

        total_len = struct.unpack_from(">H", request_data, 0)[0]
        msg_type = struct.unpack_from(">H", request_data, 2)[0]
        flags = request_data[4]
        payload = request_data[5:]  # protobuf after flags byte

        log(f"PARSING REQUEST: type={msg_type} total_len={total_len} flags={flags:#04x} payload_len={len(payload)}")
        if payload:
            self._parse_protobuf(payload, 0)

        if msg_type == 119:
            # Ping (cmdHeart) — echo back on the SAME stream.
            # Client expects a pong; without it, closes after ~500ms timeout.
            # No loop because we respond on the same stream_id, not a new one.
            resp_type = 119
            resp_flags = flags
            resp_pb = payload
        elif msg_type == MSG_UNREAL_OPEN:
            # UNREAL_OPEN handshake. Client sent MsgFromUnrealOpen{Identity}
            # where Identity is ":<client pid>" (observed: ":8688", ":25976",
            # ":18964" - the number tracks the game's PID, so it is a
            # per-process identity, NOT something we must echo numerically).
            #
            # Server must answer with the SAME msgID and MsgToUnrealOpen:
            #   f1: TimeStampSec  int64  (varint) - gate clock, unix seconds
            #   f2: ReconnectSec  int32  (varint) - reconnect grace window
            #
            # Field order/tags taken from cbc/unrealmessage.min.cbc, where the
            # emitted order is "MsgToUnrealOpen, TimeStampSec, ReconnectSec"
            # (protobufjs assigns tags in declaration order => 1 and 2).
            # Client-side proof of the names: NetworkManager logs
            #   "UnrealOpen {0}:{1} {2}:{3} ReconnectSec={4}"
            # right after handling this message.
            identity = self._pb_get_string(payload, 1)
            log(f"UNREAL_OPEN Identity={identity!r} -> MsgToUnrealOpen")

            # EXPERIMENT 22:xx: node in the travel URL = this TimeStampSec
            # (proven: URL node always equals the unix ts sent here). The URL
            # 'nz.<node>-<conn>:7777' fails InitConnect as 'invalid URL'.
            # Test with node = 1 (clean small id) to see if the failure is the
            # VALUE (unregistered node) vs the FORMAT (any nz.* host).
            pb = bytearray()
            # f1: TimeStampSec (int64, varint) - tag 0x08
            # PROBE 01:58: node in the travel URL 'nz.<node>-<conn>' traces back to this
            # TimeStampSec (via RecvConnectGate/RecvRoleLogin node). Run 01:58 used 1 ->
            # 'invalid URL: nz.1-0:7777'. Probe: node=10 (hosts: nz.10-0) to distinguish
            # "node value matters" from "URL shape always invalid".
            pb += bytes([0x08]) + self._encode_varint(10)
            # f2: ReconnectSec (int32, varint) - tag 0x10
            #     0 = no reconnect window offered; the client only stores it.
            pb += bytes([0x10]) + self._encode_varint(1)

            resp_type = MSG_UNREAL_OPEN   # SAME msgID, opposite direction
            resp_flags = 0x00
            resp_pb = bytes(pb)
        elif msg_type == MSG_CLI_ACCOUNT_LOGIN:
            # CLI_ACCOUNT_LOGIN. Client sent C2GAccountLogin{Account, Password,
            # Version, RoleIDHint}; observed wire:
            #   f1 Account  = '1'                      (SDK userId)
            #   f2 Password = 'local-bypass-token-...' (SDK token from fake_server_v2)
            #   f3 Version  = 51                       (ClientVersion)
            #
            # Server must answer with the SAME msgID and G2CAccountLogin.
            # Field layout from cbc/unrealmessage.min.cbc (declaration order,
            # confirmed by the verify strings "Code: integer expected",
            # "Dsip: string expected", "Dsport: integer expected",
            # "DedicatedData: buffer expected"):
            #   f1: Code           enum/int  (ERR_NONE = 0 => success)
            #   f2: Dsip           string    (dedicated server IP)
            #   f3: Dsport         integer   (dedicated server port)
            #   f4: DedicatedData  bytes     (serialized localpb.LoadRoleDedicatedData)
            #
            # Client-side handler: RecvCliAccountLogin (MessageHandler.min.cbc).
            # On Code==ERR_NONE it runs RecvCliAccountLoginSuccess:
            #   decode DedicatedData (LoadRoleDedicatedData{DedicatedID,
            #     CompatibleUniqueVersion, ClientLatestVersion})
            #   -> ReceiveClientLatestVersion -> SetDedicatedIDOnClient
            #   -> MarkTravelPending -> SetTargetMapId -> NzClientTravel
            #      "?RoleID=...&MapId=..." -> ClientTravel TRAVEL_Absolute
            # On Code!=0 it logs NZ_AUTOMATION_ROLE_LOGIN success=false.
            # The old echo-back behaviour produced a protobuf decode failure
            # ("invalid wire type 6 at offset 23" + TypeError reading 'ErrorID'
            # in RecvCliAccountLogin) and the endless retry loop.
            account = self._pb_get_string(payload, 1)
            log(f"CLI_ACCOUNT_LOGIN Account={account!r} -> G2CAccountLogin")

            # ---- WHAT THE CLIENT'S DECODER ACTUALLY DOES (derived, not guessed) ----
            # protobufjs/minimal generated decode() switches on (tag >>> 3) and
            # calls the TYPED reader for that field, IGNORING the wireType we put
            # on the wire. Two different payloads we sent both produced the exact
            # same client error:
            #     decode OnMessage 1001 - RangeError: index out of range: 22 + 51 > 31
            # Tracing the 31-byte payload byte by byte:
            #   idx 16  tag 0x22 (OLD) / 0x2a (NEW) -> field 4 / field 5.
            #           To end up at idx 20 the reader must have consumed only
            #           2 bytes here => that field was read as a VARINT.
            #   idx 18  tag 0x08 -> field 1 read as varint  => Code is field 1, varint. PROVEN.
            #   idx 20  tag 0x10 -> field 2 read as LENGTH-DELIMITED, taking
            #           idx 21 (0x33 = 51) as the length => 22 + 51 > 31. PROVEN.
            # So in the client's compiled schema field 4 AND field 5 are varint
            # fields, i.e. DedicatedData (a "buffer") is NOT field 4 - the naive
            # Code=1/Dsip=2/Dsport=3/DedicatedData=4 layout is disproved by the
            # wire, even though it is what the .cbc verify strings suggest.
            #
            # Therefore: probe. Send ONLY the one field whose reader type is
            # proven (Code = field 1, varint). That payload decodes cleanly under
            # EVERY candidate schema, so the client proceeds into
            # RecvCliAccountLoginSuccess and its own log names the next field it
            # needs ("decode DedicatedData" / ERR_LOAD_ROLE_DSDECODEROLEDATA /
            # SetDedicatedIDOnClient ...). Each further field is then added one at
            # a time and confirmed by a log quote.
            #
            # QG_ACCOUNT_LOGIN_PB=<hex> overrides the response payload verbatim,
            # so the probe can be iterated without editing this file.
            override = os.environ.get("QG_ACCOUNT_LOGIN_PB", "").strip()
            if override:
                resp_pb = bytes.fromhex(override.replace(" ", ""))
                log(f"CLI_ACCOUNT_LOGIN payload OVERRIDE {len(resp_pb)}B: {resp_pb.hex(' ')}")
            else:
                # Probe result: the minimal payload 08 00 DECODED CLEANLY and the
                # client reached the version check, reporting
                #   客户端版本和服务端版本不匹配,请更新游戏 / [20002] = ERR_DEDICATED_VERSION
                # ("Target Server CompatibleUniqueVersion mismatch,Local={0} Target={1}").
                # That proves field 1 is a varint code and ERR_NONE == 0, and that
                # with DedicatedData empty the decoded CompatibleUniqueVersion is 0
                # while the client's local value is 51.
                #
                # Byte-exact trace of BOTH earlier RangeErrors ("22 + 51 > 31")
                # constrains the client schema to:
                #   f1 = varint, f2 = length-delimited, f4 = varint, f5 = varint
                # (only that combination reproduces the identical error for the
                #  1/2/3/4 payload AND the 1/2/4/5 payload). So the buffer field
                #  DedicatedData is f2, not f4 as the naive declaration-order
                #  reading of the .cbc verify strings suggested.
                #
                # inner = localpb.LoadRoleDedicatedData (cbc/localmessage.min.cbc):
                #   f1 DedicatedID             int64
                #   f2 CompatibleUniqueVersion int32  <- must equal client's 51
                #   f3 ClientLatestVersion     string <- client CPPVersion 1055461
                # PROBE LOG (23:40:37, game_stdout.log):
                #   LogServer: AccountLogin 31055461.19246237 RoleID=0
                #   LogNzRobot: NZ_AUTOMATION_ROLE_LOGIN success=true role_id=0
                #   LogNzUpdate: Error: ReceiveClientLatestVersion: Check Version
                #       InCompatible and no update needed (Server=0 Current=51)
                # => the inner message decoded WITHOUT error and f3 (string) was
                #    read back verbatim, but CompatibleUniqueVersion arrived as 0
                #    even though we put varint 51 on tag 2. Unknown fields are
                #    skipped silently by protobufjs, so tag 2 in the client's
                #    LoadRoleDedicatedData is NOT CompatibleUniqueVersion.
                #    Current=51 is the client's local UniqueVersion, so the value
                #    we must land is 51 on whichever tag IS CompatibleUniqueVersion.
                # SCHEMA HISTORY (all wire-proven by client behavior):
                # 17:23 run: inner on tag 0x22 -> RangeError "22+51>40" (86948).
                # 19:59 run: lengths fixed, still 0x22 -> "28+48>46" (87124
                #   = field-6 bytes case). => DedicatedData is FIELD 6 (0x32).
                # 20:15 run: clean decode, NO RangeError. Client printed:
                #   NZ_AUTOMATION_ROLE_LOGIN success=false role_id=1 code=7777
                #   AccountLogin 127.0.0.1 Code 7777
                # => f1 ignored by handler, f2 = Dsip (string, read: "127.0.0.1"),
                #    f3 = Code varint (7777 taken as error code -> [20001]),
                #    f5 = RoleID (read: 1), f6 = DedicatedData bytes.
                # Code=0 must go on f3; f1 dropped (unknown/ignored).
                # 20:29 run: all 7 outer/inner markers (outer f4/f7, inner
                # f4-f7) silently skipped, Server=0. => version is NOT in
                # any of those slots. Bytecode extraction (calibrated on the
                # wire-proven G2CAccountLogin decode: pattern '0d <tag> c7 61
                # f8 04' lists case tags 08/12/18/20/28/32/38/40/4a) applied
                # to LoadRoleDedicatedData in localmessage.min.cbc:
                #   0x2631e3 tag 08 -> f1 varint  (DedicatedID)
                #   0x263220 tag 10 -> f2 VARINT (CompatibleUniqueVersion!)
                #   0x26325d tag 1a -> f3 string (ClientLatestVersion)
                # ONLY three fields. Inner f2 must be varint 51 (we had it as
                # string '51' -> tag 0x12 case-2 varint reader read '02' then
                # skippedType garbage: no error, no version). THE fix:
                # 20:42 run: inner f2=varint51 delivered (payload 32 16 08 01
                # 10 33 ...), still Server=0 and NO 'decode DedicatedData
                # failed' error => DedicatedData likely EMPTY, i.e. f6 was
                # silently skipped. G2C decode has THREE LEN cases: f2(Dsip),
                # f6, f9. DedicatedData may be f9 (tag 0x4a). Dual probe:
                # same inner on BOTH f6 and f9 - the wrong slot is ignored.
                clv = b"1055461.19246237"
                inner = bytearray()
                inner += bytes([0x08]) + self._encode_varint(1)       # f1 DedicatedID
                inner += bytes([0x10]) + self._encode_varint(51)      # f2 CompatibleUniqueVersion = 51
                inner += bytes([0x1a]) + self._encode_varint(len(clv)) + clv  # f3 ClientLatestVersion

                resp_pb = bytes(
                    bytes([0x12]) + self._encode_varint(9) + b"127.0.0.1"   # f2 Dsip
                    + bytes([0x18]) + self._encode_varint(0)          # f3 Code = ERR_NONE
                    + bytes([0x20]) + self._encode_varint(25301)      # f4 PROBE 03:31: Dsport candidate (30004 marker never showed up anywhere)
                    + bytes([0x38]) + self._encode_varint(30007)      # f7 marker
                    + bytes([0x40]) + self._encode_varint(10239)      # f8 = MapId (NewWorld, DT_Map row 143)
                    + bytes([0x32]) + self._encode_varint(len(inner)) + inner  # f6 DedicatedData
                    + bytes([0x4a]) + self._encode_varint(len(inner)) + inner  # f9 DedicatedData
                    + bytes([0x28]) + self._encode_varint(1)          # f5 RoleID
                )
                log(f"CLI_ACCOUNT_LOGIN probe payload: {resp_pb.hex(' ')}")

            resp_type = MSG_CLI_ACCOUNT_LOGIN   # SAME msgID, opposite direction
            resp_flags = 0x00
        elif msg_type == 10001:
            # 00:28 run discovery: after the 1001 answer the client SENDS
            # msgID 10001 (LOAD_ROLE request) {f1=0, f2=RoleID=1, f3=9,
            # f4=Gateport=25301 - values taken from our CONNECT_GATE}. Our
            # old echo of it was garbage -> RecvLoadRole crashed in
            # UpdateDsTargetData. Reply with a proper G2DLoadRole instead
            # (same msgID, opposite direction) - the structure already
            # wire-proven via the CONNECT_GATE f3 experiments:
            #   f1 Binary bytes, f2 MasterRole varint, f3 Gateip string,
            #   f4 Gateport varint (f5/f6 are string-typed, omitted).
            role_name = b"Player1"
            rb = bytearray()
            rb += bytes([0x0a]) + self._encode_varint(0)              # f1 Segment = empty
            rb += bytes([0x12]) + self._encode_varint(len(role_name)) + role_name  # f2 Name
            rb += bytes([0x1a]) + self._encode_varint(0)              # f3 Shallow = empty
            rb += bytes([0x28]) + self._encode_varint(1)              # f5 Stage = 1

            resp_pb = bytearray()
            resp_pb += bytes([0x0a]) + self._encode_varint(len(rb)) + rb  # f1 Binary
            resp_pb += bytes([0x10]) + self._encode_varint(1)         # f2 MasterRole = 1
            resp_pb += bytes([0x1a]) + self._encode_varint(9) + b"127.0.0.1"  # f3 Gateip
            resp_pb += bytes([0x20]) + self._encode_varint(25301)     # f4 Gateport
            # 00:36 run: with f5/f6 ABSENT the crash path moved from
            # UpdateDsTargetData to directly inside RecvLoadRole (undefined
            # .GetEventManager) - the handler reads a missing field. f5 is
            # wire-STRING typed; provide it as empty bytes (tag 0x2a len 0)
            # so the field exists instead of undefined:
            resp_pb += bytes([0x2a]) + self._encode_varint(0)         # f5 (string-typed) = empty
            resp_pb = bytes(resp_pb)

            resp_type = 10001    # same msgID, opposite direction
            resp_flags = 0x00
        elif msg_type == 0:
            # UNREAL_MESSAGE (msgID=0, flags=0x10): raw UE packets tunneled through
            # the gate connection. The UNzNetConnection for the travel URL wraps its
            # packets in this envelope and expects the remote DS (node:conn of the
            # URL) to answer in the same envelope. The 18:55 run showed 1Hz
            # retransmits of the UE Stateless Connect ClientHello (payload
            # 'a4 01 02 <flag> <seq> 6c ee 1b 78 00...00 <hmac>') and the echo branch
            # produced ConnectionTimeout after 30s.
            # Respond as the DS side: a UE Stateless Connect ServerChallenge.
            # v12: flags=0x12 — 0x00 routes to the JS protobuf decode path (v7),
            # 0x10 is accepted but silently ignored (v9/v10/v11: no reject, no
            # state change, 30s timeout). The Incoming dispatch dataFlag (r8b)
            # derives from the tunnel layer; bit1 of the flags byte is the
            # untested data-packet marker.
            resp_pb = self._build_ue_handshake(payload)
            resp_type = 0
            resp_flags = 0x12
        else:
            # Unknown type: echo back
            log(f"UNKNOWN MSG TYPE {msg_type}, echoing")
            resp_type = msg_type
            resp_flags = flags
            resp_pb = payload

        # Build framed response: <u16 BE total_len> <u16 BE msg_type> <u8 flags> <protobuf>
        total = 2 + 1 + len(resp_pb)
        frame = bytearray()
        frame += struct.pack(">H", total)
        frame += struct.pack(">H", resp_type)
        frame += bytes([resp_flags])
        frame += resp_pb
        return bytes(frame)

    def _build_ue_handshake(self, payload):
        """Respond to a UE StatelessConnect ClientHello tunneled in msgID=0.

        Offline analysis (HANDSHAKE_ANALYSIS.md + dumps of 0x14406bbf0 /
        0x14135ab40 / 0x14402ab50 from live memory, pid 34460):

        The payload is a bit-serialized UE control packet. Observed hello:
          a4 | 01 02 00 80 | 6c ee 1b 78 | 00*NN | <integrity tail 9-13B>
        - The u32 '01 02 00 80' (LE 0x80000201) is a UE BUNCH HEADER:
            [Ack:14 (bits 18-31)][Seq:14 (bits 4-17)][NumChunks:4 (bits 0-3)]
          => Ack=8192, Seq=32, Chunks=1. The alternating substream 0x80800201 has
          Ack=8224 (two logical bunch streams).
        - '6c ee 1b 78' is the FIRST CHUNK dword — the client's cookie. The client's
          Incoming validator (0x14403f50b) walks its cookie-entry list
          (entry: State dword @+0, Time double @+0x10, Next @+0x28) requiring
          State==0x70 — entries are created by the client's OWN hello chunks.
          v1/v2 failed because our response carried a foreign cookie ('znZZ') that
          matched no entry.
        - v4: echo the client's chunk dword back, wrapped in a bunch header whose
          Ack = the client's Seq, and keep the control prefix byte 'a2' (accepted
          by the parser in v2 — the reject happened later, at the walk).
        """
        if not payload or len(payload) < 9:
            log(f"UE-HS: payload too short ({len(payload) if payload else 0}B), echoing")
            return payload
        # Parse the hello
        ctrl = payload[0]                                   # 'a4' family
        hdr = struct.unpack_from("<I", payload, 1)[0]       # bunch header
        ack = (hdr >> 18) & 0x3FFF
        seq = (hdr >> 4) & 0x3FFF
        chunks = (hdr & 0xF) or 1
        client_chunk = payload[5:9]                         # first chunk = cookie
        log(f"UE-HS: ClientHello ctrl={ctrl:#04x} hdr={hdr:#010x} "
            f"Ack={ack} Seq={seq} Chunks={chunks} cookie={client_chunk.hex()} "
            f"full={payload.hex()}")
        # v9 (post-v7/v6 full-code analysis, HANDSHAKE_ANALYSIS.md):
        # 1. flags=0x00 (v7) routes the payload into the JS protobuf decode path —
        #    'decode OnMessage 0' error. flags=0x10 IS the raw tunnel. Back to 0x10.
        # 2. The client's control handler validates the bunch Seq/Ack against a
        #    0x2000 window around its counters (0x14403ec6c: window checks vs
        #    [rsi+0x1c84] etc.). v4/v6 rewrote the header (Seq=0, Ack=their Seq)
        #    => OUT OF WINDOW => reject at 0x14403f0ad.
        # 3. The PURE echo (original 'else' branch) NEVER errored — the client
        #    retransmitted for 30s WAITING for the real challenge: structurally
        #    accepted, semantically not an answer.
        # v9: keep the hello's ENTIRE bit layout (ctrl, header, tail — all in the
        #    client's own window), change ONLY the 4-byte chunk/cookie dword to a
        #    challenge marker. If the walk matches by entry and the state machine
        #    wants fresh cookie data, this is the minimal delta that stays valid.
        # v11 (post-v10): v10 == v9 == silently accepted + 30s wait. Ctrl byte
        # proved irrelevant. The untested hole in the matrix:
        #   v4/v6: rewritten payload + Seq=0    -> REJECTED
        #   v9/v10: echo payload + Seq=32(own)  -> accepted, ignored (own Seq => self-echo)
        #   v11:  echo payload + Seq = clientSeq+1 (33), Ack = clientSeq (32)
        # — a packet in the client's forward window (the 0x14403ec6c check requires
        # Seq > lastInSeq within 0x2000) with an otherwise pristine echo body.
        # This is the first response that is BOTH structurally native AND advances
        # the sequence — the signature of a real server packet.
        # v13 (post-v12, THE BREAKTHROUGH): flags=0x12 routed our payload to the
        # Go formater (etcd.dll, nezha/std/cluster formater.go:619) which logged
        # 'packet decode 0 <len> snappy: corrupt input' on EVERY reply — direct
        # evidence the server->client msgID=0 payload must be SNAPPY-COMPRESSED
        # (golang/snappy block format). The tunnel is asymmetric: client->server
        # raw (flags=0x10), server->client snappy via the Go formater.
        challenge_marker = b"\x5a\x5a\x6e\x7a"             # 'ZZnz' LE marker
        hdr = struct.unpack_from("<I", payload, 1)[0]
        seq = (hdr >> 4) & 0x3FFF
        resp_hdr = (seq << 18) | ((seq + 1) << 4) | (hdr & 0xF)   # Ack=their Seq, Seq=theirSeq+1
        resp = bytearray(payload)                           # exact echo of the hello
        resp[1:5] = struct.pack("<I", resp_hdr)
        resp[0] = 0xa2
        resp[5:9] = challenge_marker
        # v15 (THE decoded discriminator): the challenge-vs-data decision at
        # 0x14403ed91-edab: r14d = Chunks-1; the CHALLENGE-DATA path is taken
        # when al (challenge-pending flag) == 1 AND (Chunks-1) > ecx (a small
        # global threshold). Our echo carried Chunks=1 => r14d=0 => path
        # skipped => silent window-check reject. A real server challenge
        # carries MULTIPLE chunk dwords. v15: Chunks=2 + a second challenge
        # chunk appended after the cookie.
        # v16 (00:26 run analysis): responses structurally valid, but the
        # client drops the QUIC connection ~220ms after each response and
        # reconnects (the '3 exchanges' are reconnect cycles, not retransmits).
        # The response content doesn't satisfy the StatelessConnect state
        # machine.
        # v20-mirror (REJECT_ROOT_CAUSE.md, 30 Oct): the reject chain is PROVEN:
        # PacketHandler::Incoming (0x14235fb30) sets error only via FBitReader
        # OVERREAD (SetError, bit1 of reader+0x29); the observed 76ms reject is
        # 'Packet failed PacketHandler processing.' (NetConnection.cpp:2058) +
        # Close(27). The v19f deltas vs the hello (the only wire-proven VALID
        # structure): tail 8B vs 12B, zero-run 45B vs 30B, chunks=3 vs 2,
        # inserted chunk2. v20-mirror: reproduce the hello's EXACT byte
        # structure — same length (51B), same zero-run (30B), same tail shape
        # (01 + 11B random ending 01) — changing ONLY the header bits and ctrl:
        # a2 + Ack=their Seq(32) + Seq=theirSeq+N + Chunks=2, cookie echoed
        # unchanged. Single semantic variable: 'this is a server reply'.
        # Readout per REJECT_ROOT_CAUSE.md:
        #   reject ~76ms  -> overread is the version-14 extra-field sequence
        #   timeout       -> server responses need >=59B (size gate); re-run with
        #                    the ZERO RUN padded only (structure unchanged)
        #   no close, no retransmit -> structurally accepted; next layer opens
        self._ue_resp_count += 1
        resp_seq = (seq + self._ue_resp_count) & 0x3FFF
        # v23 (02:50 analysis): every client retransmit carries ack = 8192|N
        # (hdr #1 0x80000201 ack=8192, #2 0x80800201 ack=8224, #3 0x81000201
        # ack=8256): the TOP Ack bit (8192) is the challenge/restart flag.
        # v19f-v22 all sent ack=32 WITHOUT the 8192 bit -> the client parsed
        # our packet as NON-challenge data -> bunch-read misparse on
        # challenge-format bits -> FBitReader overread -> SetError ->
        # 'Packet failed' + Close(27). v22 run (02:49:25): 66B, 2 words,
        # client's own tail, still rejected at 213ms — word count and tail
        # are exonerated; the challenge bit is the remaining delta.
        # v23: ack = 8192 | clientSeq (= 8224 for seq 32, exactly the shape
        # of retransmit #2's header), seq = resp_seq, words = 2 (hello's own).
        # v26 (31 Oct, PROVEN via VEH SetError-caller hook + UE log record):
        # the 8192 ack bit IS bIsRestarted in the StatelessConnect
        # secret-id header. Client decoded our v23 header, saw
        # 'restart handshake request' while its cookie state != Authorised,
        # logged "Server sent restart handshake request, when we don't have
        # an authorised cookie." (StatelessConnectHandlerComponent.cpp) and
        # SetError(reader,0) -> 'Packet failed PacketHandler processing.' +
        # Close(27). The retransmits carry 8192|N because a RESTARTED client
        # hello sets that bit - the SERVER response must NOT.
        # v26: ack = plain clientSeq, no restart bit.
        resp_hdr2 = (seq << 18) | (resp_seq << 4) | (hdr & 0xF)
        resp = bytearray(payload)                        # hello's own bytes: cookie, zeros, tail
        resp[1:5] = struct.pack("<I", resp_hdr2)
        # v27: KEEP THE CLIENT'S OWN ctrl byte. v26 removed the 8192 ack bit but
        # the reject persisted (same caller 0x14408e63d, same 'restart handshake'
        # log) => bIsRestarted is NOT the ack bit. The hello ctrl varies per
        # retransmit (a4, a8) and never carries bit1; our constant 0xa2
        # (=1010_0010, bit1 SET) is the only bit the client never sends.
        # ctrl bit1 = bIsRestarted. 0xa2 requests a restart => reject.
        # v27: echo payload[0] unchanged.
        # resp[0] stays as payload[0] (client's own ctrl: a4/a8/..)
        # v20-mirror run (02:39, 31 retransmits, 30s Tick timeout): the 51-55B
        # response never reached the parser — below the >=59B size gate
        # (same silent-drop class as v9-v14). Structure untested, not rejected.
        # v21: single variable vs v20-mirror = LENGTH. Pad the ZERO RUN ONLY
        # (structure byte-for-byte identical, tail stays LAST):
        #   a2 | hdr | cookie | 00*(66-tail) | <client's own tail>
        # Readout:
        #   reject ~76ms  -> overread in version-14 extra fields (chunk2/words)
        #   silent/timeout -> size gate is not the (only) filter; dump live
        #   no retransmit, no close -> challenge accepted; next layer opens
        # v28 (31 Oct, DECODED from component disasm 0x14408eac0 -> validator
        # 0x144096fd0/0x144097480): the client's StatelessConnect validator
        # computes remaining=limit-pos and takes the SHORT branch (ours:
        # 535-87=448) which reads ONE bit at pos=87 and REQUIRES it == 1
        # (bIsChallenge of the server response). Our zero-run gives 0 ->
        # validator returns false -> caller logs 'Server sent restart
        # handshake request...' + SetError -> Close(27). All 2+3-bit flag
        # rounds (bits 72..87) must stay 0 (compared vs [comp+0x160]=0), so
        # bit 87 is the ONLY settable bit - by elimination AND by the
        # validator's read position (byte 10, bit 7).
        # v32 (31 Oct, 02:30, VALIDATOR HOOK GROUND TRUTH):
        # The validator 0x144096fd0 entry dump: reader pos=6, limit=535,
        # remaining=529. Branch selector: remaining == 0xe2(226) / 0x182(386)
        # / 1 -> LONG branch (full challenge parse); ANYTHING ELSE -> SHORT
        # branch reads ONE bit at pos=6 = ctrl byte bit6 and REQUIRES it == 1.
        # Our 67B packet (535 bits) -> 529 remaining -> SHORT -> bit6 of
        # echoed ctrl (a4) = 0 -> reject. All bit-86/87 theories were wrong:
        # the reject is decided at STREAM BIT 6 = CTRL BIT 6.
        # v32: set ctrl bit6 (0x40) AND size the packet for the LONG branch
        # (49B = 392 bits, remaining at pos 6 = 386 = 0x182) so the real
        # challenge parse runs:
        #   [ctrl|0x40][hdr 4B][cookie 4B][challenge body 40B]
        # v33 (LONG-branch field semantics): the validator reads
        #   8 bits  @6..13  = {bIsRestarted(1) bIsChallenge(1) Type(3) SecretId(3)}
        #   20 bits @14..33 = (inside hdr dword)
        #   20 bits @34..53 = (hdr/cookie boundary)
        # v34 (31 Oct 13:40): v33 FACTS: validator entry limit=384 pos=6
        # remaining=378 -> NEITHER 386 NOR 226 (the 49B packet becomes 48B
        # after the client's trailing-byte strip: limit = 48*8 = 384).
        # 'Incoming return=0x00' (no reject!) but dl=[struct+0xa]=5 vs
        # r15b=1 (expected type, set at 0x14408e409) -> MISMATCH -> ignored.
        # The 0xe2 (226) branch sets [struct+0xa] = 1 when the double at
        # [struct+0x10] > 0 and comp state == 0 -> dl=1 == r15b=1 -> ACCEPT.
        # v34: 29-byte packet (232 bits; the client strips 1 trailing byte ->
        # limit = 28*8 = 224; hmm - strip makes remaining 224-6=218, not 226.
        # To get remaining 226 AFTER strip: limit must be 232 = 29B data...
        # limit = (len-1)*8 with the trailing byte stripped. For limit=232:
        # len-1 = 29 -> len=30B; remaining = 232-6 = 226. 30 bytes total.
        ctrl_out = payload[0]                               # a4: bit6=0, bit7=1
        seq_mod = (self._ue_resp_count + 47) & 0x3FF0       # seq ≡ 0 mod 16
        hdr_v34 = (seq << 18) | (seq_mod << 4) | (hdr & 0xF)
        resp = bytearray()
        resp.append(ctrl_out)
        resp.extend(struct.pack("<I", hdr_v34))
        resp.extend(payload[5:9])                          # cookie echo
        # body: 8-bit field lands at bits 6..13 (ctrl b6,7 + hdr byte0 b0..5)
        # = 0x06 with a4 + hdr byte0 0x01 (seq_mod≡0 mod16, chunks=1).
        # 20-bit field @14..33 from hdr dword bits. Pad to 30B, last byte
        # nonzero.
        rest = bytearray(b"\x00" * (30 - 9))
        rest[0] = 0x06
        resp.extend(rest)
        resp[29] = 0x01
        import snappy
        compressed = snappy.compress(bytes(resp))
        log(f"UE-HS: ServerResponse v34 ({len(resp)}B, ctrl={ctrl_out:#04x}, "
            f"ack={seq}, Seq={resp_seq}): raw={bytes(resp).hex()}")
        return compressed

    def _build_connect_gate(self):
        """CONNECT_GATE (msgID 103) -> Ds2Gate2DsConnect payload.

        Schema from gos_work/messages.txt (decl order, verify strings in
        unrealmessage.min.cbc) and the client handler RecvConnectGate
        (MessageHandler.min.cbc: reads BusNode/BusConnID/TraceID, decodes
        LoadRole, logs 'RecvConnectGate ({0}) {1}:{2} {3}'):
          f1  ClientConnID  int
          f2  RoleID        int64
          f3  LoadRole      buffer (RoleDataBinary - synthetic minimal)
          f4  BusNode       int64   <- node for the travel URL
          f5  BusConnID     int
          f6  TraceID       int64
          f12 LoadOK        bool
        The node value: the client's gate connection node (our UNREAL_OPEN
        TimeStampSec = 1 in the current experiment). If the handler prints
        RecvConnectGate in the log, we read which args it consumed and adjust.
        """
        try:
            # SCHEMA (verified byte-exact against two decode failures):
            # 23:44: flat RoleDataBinary in f3 -> 'invalid wire type 7 at
            #   offset 16' = byte 0x4f of our 18-byte buffer parsed as field 9
            # wire 7 while the client decoded f3 LoadRole AS G2DLoadRole.
            # 23:35: G2DLoadRole with ONLY f1 Binary -> 'RangeError: 16+8>16'
            #   (decoder fell off the buffer after f1).
            # => client decodes LoadRole as G2DLoadRole with ALL 6 fields:
            #   f1 Binary(bytes, RoleDataBinary), f2 MasterRole int64,
            #   f3 Gateip string, f4 Gateport int32, f5 LoadTimeout int32,
            #   f6 Progress enum. And RoleDataBinary: f1 Segment(repeated
            #   bytes), f2 Name, f3 Shallow, f4 MapID, f5 Stage.
            # Three-level build. 23:53: error moved 16->18; tag byte with
            # wire type 7 (0xff/0x4f = MapID varint 10239) hit while the
            # reader was misaligned. DeepSeek step 2: REMOVE MapID (f4) from
            # rb so no ambiguous wire-7 bytes exist; keep the 6-field G2DLoadRole.
            role_name = b"Player1"
            rb = bytearray()
            rb += bytes([0x0a]) + self._encode_varint(0)              # f1 Segment = empty
            rb += bytes([0x12]) + self._encode_varint(len(role_name)) + role_name  # f2 Name
            rb += bytes([0x1a]) + self._encode_varint(0)              # f3 Shallow = empty
            rb += bytes([0x28]) + self._encode_varint(1)              # f5 Stage = 1
            # (f4 MapID omitted - diagnostic)

            # 00:03 run: 'RangeError: 36 + 30 > 38' byte-exact trace: client's
            # G2DLoadRole f5 (LoadTimeout) is a STRING/BYTES reader (our
            # '28 1e' varint was misread as len=30 at pos 36). PROVEN wire
            # types so far: f1 bytes, f2 varint, f3 string, f4 varint, f5
            # string(!). Drop f5/f6 - protobufjs tolerates missing optional
            # fields; if the handler needs them it will fail with null.<Name>.
            glr = bytearray()
            glr += bytes([0x0a]) + self._encode_varint(len(rb)) + rb  # f1 Binary
            glr += bytes([0x10]) + self._encode_varint(1)             # f2 MasterRole = 1
            glr += bytes([0x1a]) + self._encode_varint(9) + b"127.0.0.1"  # f3 Gateip
            glr += bytes([0x20]) + self._encode_varint(25301)         # f4 Gateport
            # f5 LoadTimeout / f6 Progress omitted (wrong wire type guess)

            role = bytes(glr)  # f3 LoadRole payload = G2DLoadRole

            # 23:11 run (DeepSeek brief analysis): ClientTravel takes node:conn
            # from RecvRoleLogin (1:0), NOT from CONNECT_GATE. 'no connection to
            # gs 1:1' = the handler does a LOOKUP of (node,conn) in the JS
            # connection registry; only the gate link (1,0) exists (client
            # itself created it: 'AddGateConnection - RunAs=Client
            # GateConnectionId=0'). => BusConnID/ClientConnID must be 0 to
            # match the existing connection. conn=1 was disproven.
            pb = bytearray()
            pb += bytes([0x08]) + self._encode_varint(0)    # f1 ClientConnID = 0 (gate conn)
            pb += bytes([0x10]) + self._encode_varint(1)    # f2 RoleID = 1
            pb += bytes([0x1a]) + self._encode_varint(len(role)) + role  # f3 LoadRole
            pb += bytes([0x20]) + self._encode_varint(10)   # f4 BusNode = 10 (gate node, PROBE 01:58)
            # f5 BusConnID: MUST be nonzero. Live-memory disasm of UNzNetDriver's URL
            # parser (0x1463436ff: test eax,eax; je -> fail): the travel URL
            # 'nz.<node>-<conn>' is split on '-' and BOTH parts are converted with
            # atoi; if EITHER is 0 the parse fails -> 'Failed to InitConnect, invalid
            # URL'. Our conn=0 always produced eax=0 => rejected. conn=1 makes the
            # URL 'nz.10-1' (hosts entry exists) with both parts nonzero.
            pb += bytes([0x28]) + self._encode_varint(1)    # f5 BusConnID = 1 (nonzero, wire-proven requirement)
            pb += bytes([0x30]) + self._encode_varint(1)    # f6 TraceID = 1
            # f13 TargetData = empty DsTargetData{}: 00:11 run crashed in
            # UpdateDsTargetData (undefined.GetEventManager) with f13 ABSENT -
            # an empty-but-present object may let the handler early-return
            # gracefully instead of dereferencing undefined.
            pb += bytes([0x6a]) + self._encode_varint(0)    # f13 TargetData = empty
            pb += bytes([0x60]) + b"\x01"                   # f12 LoadOK = true

            total = 2 + 1 + len(pb)
            frame = bytearray()
            frame += struct.pack(">H", total)
            frame += struct.pack(">H", MSG_CONNECT_GATE)
            frame += bytes([0x00])
            frame += pb
            return bytes(frame)
        except Exception as e:
            log(f"CONNECT_GATE build failed: {e}")
            return None

    def _encode_varint(self, value):
        result = bytearray()
        while value > 0x7F:
            result.append((value & 0x7F) | 0x80)
            value >>= 7
        result.append(value & 0x7F)
        return bytes(result)

    def _pb_get_string(self, data, want_field):
        """Return the length-delimited value of protobuf field `want_field`
        decoded as UTF-8, or None if the field is absent/undecodable.

        Only walks top-level tags; nested messages are skipped by length so a
        missing field never makes us mis-frame. Built on _read_varint, which is
        the same reader _parse_protobuf uses.
        """
        if not data:
            return None
        pos = 0
        try:
            while pos < len(data):
                tag, pos = self._read_varint(data, pos)
                field_number = tag >> 3
                wire_type = tag & 0x07
                if wire_type == 0:          # varint
                    _, pos = self._read_varint(data, pos)
                elif wire_type == 1:        # fixed64
                    pos += 8
                elif wire_type == 2:        # length-delimited
                    length, pos = self._read_varint(data, pos)
                    if pos + length > len(data):
                        return None
                    value = bytes(data[pos:pos + length])
                    pos += length
                    if field_number == want_field:
                        try:
                            return value.decode("utf-8")
                        except UnicodeDecodeError:
                            return None
                elif wire_type == 5:        # fixed32
                    pos += 4
                else:
                    return None             # unknown wire type: stop, don't guess
        except Exception as e:
            log(f"_pb_get_string: parse error at {pos}: {e}")
            return None
        return None

    def _parse_protobuf(self, data, depth=0):
        """Parse and log protobuf fields."""
        indent = "  " * depth
        pos = 0
        while pos < len(data):
            try:
                # Read tag
                tag, pos = self._read_varint(data, pos)
                field_number = tag >> 3
                wire_type = tag & 0x07

                if wire_type == 0:  # varint
                    value, pos = self._read_varint(data, pos)
                    log(f"{indent}field {field_number} (varint) = {value}")
                elif wire_type == 1:  # 64-bit
                    if pos + 8 > len(data):
                        break
                    value = struct.unpack_from("<Q", data, pos)[0]
                    pos += 8
                    log(f"{indent}field {field_number} (64bit) = {value}")
                elif wire_type == 2:  # length-delimited
                    length, pos = self._read_varint(data, pos)
                    if pos + length > len(data):
                        log(f"{indent}field {field_number} (bytes) len={length} TRUNCATED")
                        break
                    value = data[pos:pos+length]
                    pos += length
                    # Try to decode as string
                    try:
                        s = value.decode("utf-8")
                        if all(32 <= ord(c) < 127 or c in "\r\n\t" for c in s):
                            log(f"{indent}field {field_number} (string) = {s!r}")
                        else:
                            raise ValueError
                    except (ValueError, UnicodeDecodeError):
                        log(f"{indent}field {field_number} (bytes) len={length}")
                        log(f"{indent}  {hexdump(value, 128)}")
                        # Try nested protobuf
                        if length > 2:
                            log(f"{indent}  trying nested parse:")
                            self._parse_protobuf(value, depth + 2)
                elif wire_type == 5:  # 32-bit
                    if pos + 4 > len(data):
                        break
                    value = struct.unpack_from("<I", data, pos)[0]
                    pos += 4
                    log(f"{indent}field {field_number} (32bit) = {value}")
                else:
                    log(f"{indent}field {field_number} wire_type={wire_type} UNKNOWN, stopping")
                    break
            except Exception as e:
                log(f"{indent}parse error at pos {pos}: {e}")
                break

    def _read_varint(self, data, pos):
        result = 0
        shift = 0
        while pos < len(data):
            b = data[pos]
            pos += 1
            result |= (b & 0x7F) << shift
            if not (b & 0x80):
                break
            shift += 7
        return result, pos


async def main():
    log("=== QUIC GOS gate server starting ===")

    configuration = QuicConfiguration(
        is_client=False,
        alpn_protocols=["nezha-gos", "gos", "quic", "h3"],
    )
    configuration.load_cert_chain(CERT_FILE, KEY_FILE)

    loop = asyncio.get_event_loop()

    # 7777 added: the travel URL 'nz.X-Y:7777' may dial via Go with hosts
    # (nz.X-Y -> 127.0.0.1) to port 7777 - if nothing listens there the dial
    # fails and C++ reports 'invalid URL'. Listen QUIC on 7777 too so the
    # dial finds a live endpoint.
    for port in [25301, 25302, 7777]:
        server = await serve(
            "0.0.0.0", port,
            configuration=configuration,
            create_protocol=GOSGateProtocol,
        )
        log(f"QUIC gate listening on 0.0.0.0:{port}")

    log("QUIC gate server ready. Waiting for connections...")
    await asyncio.Event().wait()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log("QUIC gate server stopped")
