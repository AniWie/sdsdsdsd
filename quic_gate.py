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


def snappy_compress_compat(data):
    """v45: literal-only snappy encoder.

    The 04:00 run proved the client's Go-side snappy decoder (etcd.dll,
    formater.go:619 'packet decode 0 10 snappy: corrupt input') rejects
    streams that python-snappy's C decoder accepts: python's compressor
    emitted a copy tag ('01 0b' in the 04:11 frame) whose offset decodes
    as 0 under the strict golang/snappy layout — python is lenient, Go
    returns ErrCorrupt, the whole UE tunnel frame is dropped, the
    reliable layer never sees our replies (cli_ack frozen at 0xfffc,
    bunch parser never called, 30s timeout).

    Fix: emit ONLY literal tags (universally compatible — every snappy
    decoder accepts literals). Compression ratio is worse, but our
    packets are <200B. Wire-verified roundtrip locally.
    """
    out = bytearray()
    n = len(data)
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    i = 0
    while i < len(data):
        chunk = data[i:i + 60]
        out.append(((len(chunk) - 1) << 2) | 0)
        out += chunk
        i += 60
    return bytes(out)


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
            # v38: after the stateless Ack completes, the client moves to the
            # PacketHandler RELIABLE component layer: packets
            # '04 <u16 ack LE> <u16 seq+flag LE> <history 4B> <data...>'
            # (handshake version 4). The FIRST client packet carries the
            # 'nothing acked yet' sentinel ack 0xfffc; after it accepts our
            # first reply the ack field carries OUR seq (e.g. 00 00) — so the
            # discriminator must be the version byte + structure, NOT the
            # ack value (v38.1 bug: 'fc ff' check only matched the sentinel
            # and all later reliable packets fell into the StatelessConnect
            # builder -> garbage replies -> 30s timeout).
            if len(payload) >= 9 and payload[0] == 0x04:
                resp_pb = self._build_reliable_reply(payload)
            else:
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
        # v35 (fix from the Discord analysis): the ClientHello is a
        # LITTLE-ENDIAN bitstream starting at bit 0 (stream bit N lives in
        # byte N//8 at bit N%8; every field is serialized LSB-first), NOT a
        # UE bunch header at byte 1. payload[1:5] == 0x80000201 is NOT
        # Ack/Seq/Chunks — those bits ARE the StatelessConnect fields:
        #   bits 0-1   SessionID        bits 2-4   ClientID
        #   bit  5     Handshake = 1    bit  6     RestartHandshake
        #   bits 7-14  MinVersion       bits 15-22 CurrentVersion
        #   bits 23-30 PacketType (0=Initial, 1=Challenge, ...)
        #   bits 31-38 SentHandshakePacketCount
        #   bits 39-70 NetworkVersion (u32, LSB-first)
        #   bits 71-86 NetworkFeatures (u16)
        #   bit  87    SecretId (1 bit)
        #   bits 88+   body: double timestamp, 20-byte cookie, random,
        #              terminating bit, zero padding
        # Proof of bit order: hello 0xa4 -> LSB-first bits2-4 = ClientID 1,
        # matching the client log 'Stateless Handshake ... CachedClientID: 1'.
        # The old v32/v34 code copied the client's header bytes and flipped
        # MSB-first bits 23-30, which the LSB-first validator decoded as a
        # wrong PacketType (5) -> challenge silently ignored -> 30s timeout.
        if len(payload) < 11:
            return payload

        def rd(n, pos):
            v = 0
            for i in range(n):
                v |= ((payload[(pos + i) >> 3] >> ((pos + i) & 7)) & 1) << i
            return v, pos + n

        pos = 0
        session_id, pos = rd(2, pos)
        client_id, pos = rd(3, pos)
        handshake_bit, pos = rd(1, pos)
        restart, pos = rd(1, pos)
        min_version, pos = rd(8, pos)
        cur_version, pos = rd(8, pos)
        pkt_type, pos = rd(8, pos)
        sent_count, pos = rd(8, pos)
        network_version, pos = rd(32, pos)
        network_features, pos = rd(16, pos)
        secret_id, pos = rd(1, pos)
        log(f"UE-HS: parsed sid={session_id} cid={client_id} hs={handshake_bit} "
            f"restart={restart} minVer={min_version} curVer={cur_version} type={pkt_type} "
            f"sent={sent_count} netVer={network_version:#010x} feats={network_features:#06x} "
            f"secret={secret_id}")

        body_pos = 88
        if pkt_type == 2 and len(payload) >= (88 + 64 + 160) // 8: 
            ts_bits = 0
            for i in range(64):
                ts_bits |= ((payload[(body_pos + i) >> 3] >> ((body_pos + i) & 7)) & 1) << i
            cookie_bits = bytearray(20)
            for i in range(160):
                cookie_bits[i >> 3] |= ((payload[(body_pos + 64 + i) >> 3] >> ((body_pos + 64 + i) & 7)) & 1) << (i & 7)
            self._last_resp_ts = ts_bits
            self._last_resp_cookie = bytes(cookie_bits)
            log(f"UE-HS: Response body ts_bits={ts_bits:#018x} cookie={bytes(cookie_bits).hex()}")

        out_bits = []

        def wr(v, n):
            for i in range(n):
                out_bits.append((v >> i) & 1)

        wr(session_id, 2)
        wr(client_id, 3)
        out_bits.append(1)
        out_bits.append(0)
        wr(min_version, 8)
        wr(cur_version, 8)
        if pkt_type == 2:
            reply_type = 3
        else:
            reply_type = 1
        wr(reply_type, 8)
        wr(sent_count, 8)
        wr(network_version, 32)
        wr(network_features, 16)
        out_bits.append(secret_id)

        if reply_type == 3 and getattr(self, "_last_resp_cookie", None) is not None:
            wr(struct.unpack("<Q", struct.pack("<d", -1.0))[0], 64)
            cookie_ack = bytearray(self._last_resp_cookie)
            cookie_ack[0:4] = b"\x00\x00\x00\x00"
            for b in cookie_ack:
                wr(b, 8)
        else:
            ts = time.time()
            wr(struct.unpack("<Q", struct.pack("<d", ts))[0], 64)
            cookie = os.urandom(20)
            for b in cookie:
                wr(b, 8)

        import random as _random
        while len(out_bits) < 384:
            out_bits.append(_random.getrandbits(1))
        out_bits.append(1)
        while len(out_bits) < 392:
            out_bits.append(0)

        out = bytearray()
        for byte_i in range(392 // 8):
            b = 0
            for bit_i in range(8):
                b |= out_bits[(byte_i << 3) + bit_i] << bit_i
            out.append(b)

        log(f"UE-HS: ServerReply type={reply_type} ({len(out)}B): raw={bytes(out).hex()}")
        # v45: literal-only snappy (python-snappy's copy tags are rejected
        # by the client's Go decoder — see snappy_compress_compat).
        return snappy_compress_compat(bytes(out))

    def _build_reliable_reply(self, payload):
        # v38.2: UE 5.5 FReliableHandlerComponent layer (post-stateless
        # phase). Client packet layout (byte-aligned, wire-verified):
        #   [0]      0x04 = reliable handshake version
        #   [1:3]    u16 LE acked-seq (0xfffc sentinel on the FIRST packet,
        #            then the seq of OUR last packet they accepted)
        #   [3:5]    u16 LE this packet's seq; bit14 (0x4000) = flag
        #            (set on data resends after our reply was accepted)
        #   [5:9]    32-bit sequence history (000000c0 early on)
        #   [9:]     channel-serialized data (bunches / NMT messages)
        # 20:27 run proof: after our first reply (our seq 0) the client's
        # next packets carried ack=00 00 (= our seq 0) — the reliable ack
        # exchange WORKS; only the dispatcher was broken (v38.1).
        # Reply: ack the client's raw seq (mask off the 0x4000 flag bit),
        # advance our own seq, copy their history word, echo their data.
        import struct as _s
        raw = _s.unpack_from("<H", payload, 3)[0]
        cli_seq = raw & 0x3FFF
        cli_ack = _s.unpack_from("<H", payload, 1)[0]
        if not hasattr(self, "_rel_seq"):
            self._rel_seq = 1               # seq 0 was consumed by the
                                             # first exchange (client acked it)
        ack = cli_seq                        # ack = their last seq
        data = payload[9:]
        out = bytearray()
        out.append(0x04)
        out += _s.pack("<H", ack)
        out += _s.pack("<H", self._rel_seq)
        self._rel_seq = (self._rel_seq + 1) & 0xFFFF
        out += payload[5:9]                  # history word: echo client's
        # v40: wire-crib analysis (20:56 run):
        #   - The game EXE is packed (static strings/code don't match live
        #     memory) — no offline disasm possible. Only wire bytes work.
        #   - Client A-packets (21B): only byte[0] varies across retransmits
        #     (ff/c9/76/ed) => byte0 = per-attempt CRC; bytes[1:] stable:
        #     '4f 00 04 e0 bf 00 18 00 08 c8 e6 be 81 07 00 00 00 00 00 18'.
        #   - byte[1]: A=0x4f, B(125B)=0x48, 2B-packets=0x0f/0x0e.
        #     bits0-2 look like a 3-bit TYPE (A=7, B=0), bit6 = has-body.
        #   - v38 (verbatim echo) -> BunchHeaderOverflow (client's own hdr
        #     parses as Chunks=15 -> overflow), v39 (our bunch, no NZ hdr)
        #     -> 'Failed to read PacketHeader' — so the client expects a
        #     NZ 2-byte packet header [crc8][type byte] BEFORE the bunch,
        #     which v39 dropped.
        # Experiment E1: reconstruct the NZ header: type byte = client's
        # byte[1] (0x4f style), crc byte = COPY the client's byte[0] (crc
        # of unchanged content may stay valid), then a bunch with sane
        # header (Chunks=1) carrying the client's own body. If crc is
        # content-derived it survives since we only alter the bunch hdr.
        # v41 (22:05 run breakthrough): the client's A-packet data[6:]
        # '00 18 00 08 c8 e6 be 81 07 00 00 00 00 00 18' decodes as a UE
        # bunch with LSB-first bits: ChIndex(10)=0, ChType(2)=2, bOpen=1,
        # bClose/bDormant/bReliable=0 — THE CONTROL-CHANNEL OPEN BUNCH
        # carrying NMT_Hello. The first 6 data bytes 'ff 4f 00 04 e0 bf'
        # are the NZ driver packet header (crc + type + length/flags).
        # v40 reached deep: 'String is too large' + 'Channel name
        # serialization failed' — the client parsed our bunch structurally
        # and tried to read ChName from our crafted bytes.
        # E2: echo the client's NZ 6-byte header + its bunch VERBATIM.
        # The client then sees its own valid control bunch coming back
        # (ChIndex=0, bOpen) — watch what it does; if it accepts, the next
        # step is crafting a proper server NMT_Welcome bunch.
        # v42 (22:2x VEH-tracer run, the decisive dump): the tracer showed
        # the client's reliable component TRANSFORMS our packet:
        #   our '04 ack seq hist | data...'  ->
        #   bunch '[Ack|Seq|Chunks] chunk0 | <2 bits><our data bits>'
        # i.e. the bunch header IS GENERATED from our reliable ack/seq
        # (bunch.ack = our seq, bunch.seq = 0, chunk0 = 0), and our DATA
        # bits are re-emitted with 2 extra bits inserted at the head.
        # The parse then walks: 32b hdr + 32b chunk + ChIndex(10) +
        # ChType(2) + 8 flag bits (positions 64->84) + ChName FString
        # (pos 84..111) — our echoed data failed in the ChName/NumBits
        # region (SetError requested=8160).
        # v42: craft the DATA as a proper server control bunch body:
        #   ChIndex=0, ChType=0, bOpen=1, other flags 0, ChName len 0,
        #   NumBits=0. Note: the 2 inserted bits shift our fields by +2,
        # so we PREPEND 2 dummy bits to compensate (our bit2 lands where
        # the parser expects bit0 of ChIndex... actually the parser's
        # ChIndex starts at out bit 64 = our data bit -2: the inserted
        # bits ARE part of its field stream. To keep ChIndex=0 we simply
        # start our data with enough zero bits that ChIndex reads 0.
        body_bits = []

        def wrb(v, n):
            for i in range(n):
                body_bits.append((v >> i) & 1)

        # v43.1 — REVERTED the v43 offset=62 before any run (pre-run
        # fact-check): re-derivation from the 23:10 trace (the only run
        # where bunch-parser positions were logged) shows the parser
        # consumed output bits 0..63 (the component's own [Ack|Seq|Chunks]
        # + chunk0 header) and the channel's bunch FIELDS start at output
        # bit 64 = DATA section bit 0 = [1,1] (component-inserted) + our
        # body bit 0. So fields belong at body bit 0 as in v42.6 — v43's
        # +62 shift would have misplaced everything 62 bits too late.
        # OPEN QUESTION (needs the one-shot hooks fixed to observe):
        # the [1,1] prefix pollutes the low bits of the first field, so
        # ChIndex reads >= 3 — yet no BunchBadChannelIndex ever fired.
        # Field widths unconfirmed. Keep v42.6 layout; calibrate NumBits
        # via QG_NUMBITS env (0 / 264 comparison run pair).
        import os as _os
        # v45.2: DEFAULT = the EXACT wire-proven accepted layout (v42.4,
        # 23:45 run — the only config where the client ever acked our
        # reliable packets, cli_ack 0x0004->0x0008->0x0018):
        #   ChIndex(10)=0, ChType(2)=0, bOpen(12)=1, 9 flag bits 0,
        #   ChName(8)=0, NMT id=1 at bit 30, 64 bits NMT fields,
        #   3 terminator bytes '01 01 01'. NO NumBits field, bReliable=0.
        #   Body hex: '00 10 00 40 00*33 01 01 01' (43B).
        # QG_NUMBITS: -1 (default) = this exact layout; >=0 inserts a
        # 16-bit NumBits field before the NMT id (calibration only —
        # untested, correlates with cli_ack freeze in v42.6-43.1).
        numbits_field = int(getattr(_os.environ, "QG_NUMBITS", "-1") or -1)
        wrb(0, 12)      # ChIndex(10)=0 + ChType(2)=0
        wrb(1, 1)       # bOpen = 1
        wrb(0, 9)       # flags: bClose/bDormant/bReliable=0/spares (v42.4 width)
        wrb(0, 8)       # ChName length = 0
        if numbits_field >= 0:
            wrb(numbits_field, 16)   # NumBits (calibration via QG_NUMBITS)
        # NMT payload: control-channel message.
        wrb(1, 8)       # NMT message id = 1 (NMT_Welcome)
        # v42.4 (23:27 run): the channel reader exhausts the bunch body
        # (reader pos hits limit) before reading the NMT fields — the
        # payload must be large enough for NMT_Welcome's field set
        # (EngineNetVersion u32, NetCL u32, FGuid 16B, GameName FString,
        # checksummed ...). Pad generously; zero-filled fields will drive
        # a SPECIFIC 'wrong version' complaint in the game log, which
        # calibrates the exact layout.
        wrb(0, 256)     # 32B of NMT fields (to be calibrated)
        log(f"UE-REL: body_bits={len(body_bits)} numbits_field={numbits_field} "
            f"v45.2-exact-v42.4-layout bOpen=1 bReliable=0 ChName=0")
        while len(body_bits) % 8:
            body_bits.append(0)
        body = bytearray()
        for i in range(len(body_bits) // 8):
            b = 0
            for j in range(8):
                b |= body_bits[i * 8 + j] << j
            body.append(b)
        # v42.1: the PacketHandler dispatcher reads the LAST byte of the
        # packet FIRST (0x14235fb6e: movzx ecx, byte [rax+rcx-1]; test cl;
        # je fail) — a trailing 0x00 is the 'ZeroLastByte' reject and our
        # 15B reply ended in 0x00 (tracer: 'PH early ret failure' with no
        # component processing at all). All good packets end nonzero
        # (0x01/0x18/0xc0): the terminating bit. Pad the body to a
        # nonzero last byte.
        while len(body) < 8 or body[-1] == 0:
            body.append(0x01 if len(body) % 4 == 0 else 0x00)
        # recompute last byte: make sure it's nonzero
        if body[-1] == 0:
            body[-1] = 0x01
        # v42.3 (23:21 run): the 26B packet's final 0x01 byte got LOST
        # somewhere in the client's snappy/tunnel path (tracer: pv.bytes=25
        # vs our 26; 'Received packet with 0's in last byte' -> ZeroLastByte
        # close) while the earlier 18B packet's terminator survived. End
        # with TWO 0x01 bytes so losing one still leaves a nonzero tail.
        # v42.5 (23:32 run): the reliable component's +2-bit repack shifts
        # our terminator bits and DROPS the overflow — our trailing
        # '01 01 01' became '04 04 00' (last byte 0x00 => '0's in last
        # byte' warning on every packet => NetFaultState QuotaLimit =>
        # ZeroLastByte close). Two extra 0x01 bytes guarantee a set bit
        # survives the shift in the final output byte.
        body += b"\x01\x01\x01\x01"
        out += bytes(body)
        log(f"UE-REL: cli_ack={cli_ack:#06x} cli_seq={cli_seq} (raw={raw:#06x}) "
            f"ack={ack} crafted_bunch={bytes(body).hex()}")
        # v45: literal-only snappy (see snappy_compress_compat docstring).
        return snappy_compress_compat(bytes(out))

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
