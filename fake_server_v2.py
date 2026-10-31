#!/usr/bin/env python3
# v2: activation (19030/80) + fake CDN/confserver for NzUpdate version checks.
# Serves "current version" JSON for any *Version.json / versionfile request so
# NzUpdate concludes the client is up to date. Logs every request so we learn
# the exact paths/fields the game asks for.
import json
import socket
import ssl
import datetime
import os
import sys
import io
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

CERT_DIR = r"D:\Games\WeiMianYe\bypass\certs"
SERVER_CHAIN = os.path.join(CERT_DIR, "server.pem")
SERVER_KEY = os.path.join(CERT_DIR, "server.key")
CRL_FILE = os.path.join(CERT_DIR, "crl.crl")
ROOT_CER = os.path.join(CERT_DIR, "bypass-local-root.cer")
LOG = r"D:\Games\WeiMianYe\bypass\logs\activation.log"

GAME_VERSION = "0.3.17.18.51"
LAUNCHER_VERSION = "1.0.8.380"

# --- transparent CDN proxy (game asset download) ---
# Real endpoints, pinned IPs (DoH fallback) so the OS hosts file (127.0.0.1) is
# bypassed. The game downloads its missing files through us as an ordinary CDN
# client: we fetch from the real server and stream back, caching on disk.
PROXY_CACHE = r"D:\Games\WeiMianYe\bypass\cache"
UPSTREAM_TLS = {
    "eee-cdn.game.ruyi.cn": "42.236.4.215",
    "eee-confserver.game.ruyi.cn": "129.211.238.117",
}
UPSTREAM_HTTP = {
    "confserver.tpo.xiaozhigame.com": "129.211.238.117",
}
# Requests whose path starts with one of these go upstream; rest stays fake.
PROXY_PREFIXES = ("/cb1/assetpak/", "/cb1/basepackage/")


def _doh_resolve(host):
    try:
        import urllib.request
        import urllib.parse
        url = "https://1.1.1.1/dns-query?name=" + urllib.parse.quote(host) + "&type=A"
        req = urllib.request.Request(url, headers={"accept": "application/dns-json"})
        with urllib.request.urlopen(req, timeout=10) as r:
            ans = json.loads(r.read().decode("utf-8"))
        for a in ans.get("Answer", []):
            if a.get("type") == 1:
                return a["data"]
    except Exception as e:
        log(f"DoH resolve failed for {host}: {e}")
    return None


import socket as _socket

def _cache_key(host, path):
    return host.replace(":", "_") + "_" + path.replace("/", "_").replace("?", "_")[-180:]


def _proxy_serve(self, host, port, use_tls, path):
    """Stream from upstream to game client while simultaneously caching to disk.
    If already cached, serve directly from disk (fast path)."""
    key = _cache_key(host, path)
    cache_path = os.path.join(PROXY_CACHE, key)
    ext = path.lower().split(".")[-1] if "." in path else ""
    ctype = {"json": "application/json", "md5": "text/plain"}.get(ext, "application/octet-stream")

    # Fast path: already cached
    if os.path.exists(cache_path):
        try:
            size = os.path.getsize(cache_path)
        except OSError:
            size = None
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        if size is not None:
            self.send_header("Content-Length", str(size))
        self.end_headers()
        with open(cache_path, "rb") as f:
            while True:
                chunk = f.read(1 << 20)
                if not chunk:
                    break
                self.wfile.write(chunk)
        return

    # Upstream fetch: stream to client + cache simultaneously
    os.makedirs(PROXY_CACHE, exist_ok=True)
    ip = UPSTREAM_TLS.get(host) or UPSTREAM_HTTP.get(host) or _doh_resolve(host)
    if not ip:
        self.send_response(502)
        self.send_header("Content-Length", "0")
        self.end_headers()
        return

    try:
        if use_tls:
            ctx = ssl.create_default_context()
            sock = _socket.create_connection((ip, port), timeout=120)
            tls_sock = ctx.wrap_socket(sock, server_hostname=host)
            conn = http.client.HTTPSConnection(host, port, timeout=300)
            conn.sock = tls_sock
        else:
            conn = http.client.HTTPConnection(ip, port, timeout=300)

        conn.request("GET", path, headers={"Host": host, "User-Agent": "WME-Proxy"})
        r = conn.getresponse()

        self.send_response(r.status)
        self.send_header("Content-Type", ctype)
        cl = r.headers.get("Content-Length")
        if cl:
            self.send_header("Content-Length", cl)
        self.end_headers()

        tmp = cache_path + ".tmp"
        total = 0
        try:
            with open(tmp, "wb") as f:
                while True:
                    chunk = r.read(1 << 20)  # 1 MB chunks
                    if not chunk:
                        break
                    f.write(chunk)
                    self.wfile.write(chunk)
                    total += len(chunk)
            conn.close()
            os.replace(tmp, cache_path)
            log(f"  upstream {host} -> {r.status} {total}B streamed+cached")
        except Exception as e:
            conn.close()
            try:
                os.remove(tmp)
            except OSError:
                pass
            log(f"  upstream stream interrupted {host}{path}: {e} ({total}B transferred)")
    except Exception as e:
        log(f"  upstream connect error {host}{path}: {e}")
        try:
            self.send_response(502)
            self.send_header("Content-Length", "0")
            self.end_headers()
        except Exception:
            pass


# Plausible version payloads — one of these should satisfy NzUpdate's parser.
def version_payloads():
    d = {"version": GAME_VERSION, "assetVersion": GAME_VERSION,
         "resourceVersion": GAME_VERSION, "resVersion": GAME_VERSION,
         "packageVersion": GAME_VERSION, "forceUpdate": False,
         "force_update": False, "mandatory": False, "url": "", "patchUrl": "",
         "md5": "", "size": 0, "files": []}
    return [
        {"code": 0, "message": "ok", "data": d},
        {"version": GAME_VERSION, "forceUpdate": False},
        d,
    ]


# Launcher self-update probe (VersionProbeServiceAdapter). The launcher log
# shows it accepted a 172-byte response and read "版本列表=..." from it, so the
# version list must be present. Field names recovered from the launcher log:
#   VersionProbeServiceAdapter / "Launcher version response is empty or invalid"
def launcher_version_payload():
    return {
        "code": 0, "message": "ok",
        "data": {
            "version": LAUNCHER_VERSION,
            "versions": [LAUNCHER_VERSION],
            "versionList": [LAUNCHER_VERSION],
            "latestVersion": LAUNCHER_VERSION,
            "forceUpdate": False,
        },
        "version": LAUNCHER_VERSION,
        "versions": [LAUNCHER_VERSION],
        "latestVersion": LAUNCHER_VERSION,
        "forceUpdate": False,
    }


# BaseVersion.json — read by BOTH the launcher (GameConfig "从manifest读取到游戏版本",
# and it then demands "BasepackageVersion") and the game's NzUpdate (cached copy in
# Saved/PersistentDownloadDir/HotfixDir/config/versionfile/WindowsClient/Version.json
# contained exactly {"version","assetVersion"}).
def base_version_payload():
    # Game's NzUpdate reads: CPPVersion, AssetVersion, AssetPatchVersion,
    # CloudDocVersion, UniqueVersion, CompatibleUniqueVersion.
    # Local game build: cl=1055461, version=5.5.4-1055461, asset_version=0.3.17.18.51,
    # CloudDocVersion=1055461.19246237, UniqueVersion=51, CompatibleUniqueVersion=51.
    # If CPPVersion parses as 0 / UniqueVersion as 1 -> "Handle Start Up Error:[1.16.3e9]
    # BaseVersionTooOld" dialog "检测到你的游戏版本过低" -> game exits.
    return {
        "version": GAME_VERSION,
        "CPPVersion": 1055461,
        "AssetVersion": GAME_VERSION,
        "AssetPatchVersion": -1,
        "CloudDocVersion": "1055461.19246237",
        "UniqueVersion": 51,
        "CompatibleUniqueVersion": 51,
        "BasepackageVersion": GAME_VERSION,
        "basepackageVersion": GAME_VERSION,
        "BaseVersion": GAME_VERSION,
        "hotfixVersion": "",
    }


def log(msg):
    line = f"[{datetime.datetime.now().isoformat(timespec='seconds')}] {msg}"
    print(line, flush=True)
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(line + "\n")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _reply(self, obj, status=200):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _serve_file(self, path, ctype):
        try:
            with open(path, "rb") as f:
                data = f.read()
        except OSError:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b""
        try:
            req = json.loads(raw.decode("utf-8")) if raw else {}
        except Exception:
            req = {}
        log(f"POST {self.path} headers={{X-Request-Id={self.headers.get('X-Request-Id')}, "
            f"X-Signature={self.headers.get('X-Signature')}}}")
        log(f"  body={raw.decode('utf-8', errors='replace')[:2000]}")
        path = self.path.split("?")[0]
        # ================= SDK LOGIN (cn-open.jx.ruyi.cn) =================
        # OkHttpRsp format: {"code":0,"msg":"ok","data":...}; Yes => code==0.
        # No signature check on responses (PlatformHttp.Parse reads body only).
        # Flow: InitManagerImpl.LaunchInit -> POST device/launch -> Launch.Parser
        #   (global/gateway/webLogin must be present, not null-safe -> NRE kills init)
        #   Login() -> POST login/before -> template.Login -> POST account/login/sms
        #   -> RealName Query -> GET identity/status (data:18) -> OnEnterGame
        #   -> LoginVerify.Verify -> POST login/after (ClientVerifyResult)
        #   -> GET query/login/after (surveys) -> OnClientVerifySuccess
        if "device/launch" in path:
            # remoteParams ("params" list of {key,value}) all optional (TryGetValue).
            # clientServer=true (else "Client Server Disabled"), clientLogger=true.
            # Request "data" is DES-encrypted with app_key — we don't need to read it.
            log("  -> 200 sdk device/launch (full Launch bean)")
            self._reply({
                "code": 0, "msg": "ok",
                "data": {
                    "params": [],
                    "global": {
                        "countryCode": "CN", "country": "中国",
                        "province": "", "city": "",
                        "clientServer": True, "clientLogger": True,
                    },
                    "gateway": {
                        "debug": False, "gatewayId": 1, "gatewayName": "local",
                        "gatewayParams": {}, "appReview": False, "appDebug": False,
                    },
                    "webviews": [],
                    "webLogin": {"urlApple": "", "urlFacebook": "", "urlGoogle": ""},
                },
            })
            return
        if "query/login/before" in path:
            # OMS query/login/before — never called in decompiled flow, but keep
            # the surveys shape in case a later SDK build asks for it as POST.
            log("  -> 200 sdk oms query/login/before (no surveys)")
            self._reply({"code": 0, "msg": "ok", "data": {"surveys": []}})
            return
        if "query/login/after" in path:
            # OmsLoginAfter is GET in NetPlatform.cs:189 — this POST branch is a
            # safety net only. {"surveys": []} -> LoginAfter bean, no surveys.
            log("  -> 200 sdk oms query/login/after (no surveys, POST fallback)")
            self._reply({"code": 0, "msg": "ok", "data": {"surveys": []}})
            return
        if "login/before" in path:
            # SDK_USER_LOGIN_BEFORE -> Dictionary<string,object> data — {} is fine.
            log("  -> 200 sdk login/before")
            self._reply({"code": 0, "msg": "ok", "data": {}})
            return
        if "login/after" in path:
            # LoginVerify.Verify -> ClientVerifyResult: token+ticket go to the GAME
            # SERVER via OnClientVerifySuccess. No client-side signature check; the
            # game server (gate_server.py) is the next gate.
            # targetServer=1, newUser=true, CODE_ACTIVATE=2 avoided.
            log("  -> 200 sdk login/after (ClientVerifyResult)")
            self._reply({
                "code": 0, "msg": "ok",
                "data": {
                    "userId": "1",
                    "userChannelId": "comwin",
                    "openId": "100000001",
                    "token": "local-bypass-token-4a7f9c2e",
                    "ticket": "local-bypass-ticket-77e1b0d5",
                    "newUser": True,
                    "targetServer": 1,
                },
            })
            return
        if "account/login" in path:
            # sms / custom / sandbox — accept ANY credentials, return fixed account.
            # OpenData: openType(str), openId(long), openToken, openName, extend.
            log(f"  -> 200 sdk account login OK ({path}, user={req.get('username') or req.get('phone')})")
            self._reply({
                "code": 0, "msg": "ok",
                "data": {
                    "openType": "sms",
                    "openId": 100000001,
                    "openToken": "local-bypass-token-4a7f9c2e",
                    "openName": "Player",
                    "extend": "",
                },
            })
            return
        if "login" in path and "service-user" not in path and "launcher" not in path:
            # any other service-open login endpoint (qr login etc.) — same account
            log(f"  -> 200 sdk generic login OK ({path})")
            self._reply({
                "code": 0, "msg": "ok",
                "data": {
                    "openType": "qr",
                    "openId": 100000001,
                    "openToken": "local-bypass-token-4a7f9c2e",
                    "openName": "Player",
                    "extend": "qrcode",
                },
            })
            return
        # ================= END SDK LOGIN =================
        if "cd-key/redeem" in path or "survey/award" in path:
            # OMS_CD_KEY / OMS_SURVEY_AWARD — accept, deliver "success" payload.
            log(f"  -> 200 sdk oms redeem/award ok ({path})")
            self._reply({"code": 0, "msg": "ok", "data": {"status": "ok", "awards": []}})
            return
        if "service-order" in path:
            # create/pay/purchase/status etc. — T is dynamic/Dictionary, any data.
            log(f"  -> 200 sdk order endpoint ok ({path})")
            self._reply({"code": 0, "msg": "ok", "data": {"orderId": "local-1", "status": 1}})
            return
        if "cdkey" in path and ("verify" in path or "validate" in path or "bind" in path):
            now = datetime.datetime.now(datetime.timezone.utc)
            expiry = now + datetime.timedelta(days=3650)
            resp = {
                "code": 0, "message": "ok", "error_code": "",
                "request_id": self.headers.get("X-Request-Id", ""), "trace_id": "",
                "data": {
                    "code": req.get("code", ""),
                    "device_code": req.get("device_code", ""),
                    "passed": True, "allowed": True, "bound": True,
                    "bind_status": "BindSuccess",
                    "activated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "expire_at": expiry.strftime("%Y-%m-%dT%H:%M:%SZ"),
                },
            }
            log(f"  -> 200 cdkey OK")
            self._reply(resp)
        elif "version" in path.lower():
            log(f"  -> 200 version payload")
            self._reply(version_payloads()[0])
        else:
            # Catch-all for SDK POST telemetry (event/report, event/online,
            # event/offline per NetPlatform.cs) — OkHttpRsp wants "msg", not
            # "message"; code==0 -> Yes.
            log("  -> 200 generic ok")
            self._reply({"code": 0, "msg": "ok", "message": "ok", "data": {}})

    def do_HEAD(self):
        # NzContentDownloader does HEAD before GET (config download); python's
        # BaseHTTPRequestHandler returns 501 for HEAD by default, and the game
        # logs "HEAD request failed with HTTP 501 ... falling back to full
        # download". Answer 200 with Content-Length from the GET payload path
        # would require duplication; simplest correct behaviour: 200 empty.
        path = self.path.split("?")[0]
        host = (self.headers.get("Host") or "").split(":")[0]
        log(f"HEAD {self.path} host={host}")
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        path = self.path.split("?")[0]
        low = path.lower()
        host = (self.headers.get("Host") or "").split(":")[0]
        log(f"GET {self.path} host={host}")
        # --- transparent CDN proxy: game asset download from the real server ---
        if path.startswith(PROXY_PREFIXES):
            if host in UPSTREAM_TLS:
                log(f"  -> proxy (TLS) {host}")
                _proxy_serve(self, host, 443, True, self.path)
            elif host in UPSTREAM_HTTP:
                log(f"  -> proxy (HTTP) {host}")
                _proxy_serve(self, host, 9080, False, self.path)
            else:
                log(f"  -> 404 no upstream for host {host}")
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()
            return
        # --- game NzContentDownloader: /cb1/assetpak/WindowsClient/{v}/BuildManifest-*.json ---
        # The REAL manifest (414 files, 22 GB) is fetched from the CDN via the proxy
        # above (/cb1/assetpak/ prefix), so the game downloads exactly what's missing.
        # This branch stays only for hosts not in UPSTREAM_* — serves the locally
        # cached real manifest if present, else empty (no diff).
        if "buildmanifest" in low:
            real = os.path.join(PROXY_CACHE, "BuildManifest-real.json")
            if os.path.exists(real):
                log("  -> 200 BuildManifest (real, from cache)")
                self._serve_file(real, "application/json")
            else:
                log("  -> 200 BuildManifest (empty files)")
                self._reply({"version": GAME_VERSION, "files": []})
            return
        # --- REAL config proxy: compat_matrix.json + system_switch.json ---
        # ROOT CAUSE of the infinite world-load (found 2026-10-17):
        #   On the real confserver BOTH of these are WinZip-AES-256 ZIPs whose
        #   inner member is `serverlist.json`. The game downloads them (this IS
        #   NzServerSetting.ServerListURL), decrypts with its own built-in
        #   password and fills NzServerSetting.ServerList = TArray<{ServerIP,
        #   ServerName, Gate}>.
        #   Our old fake answered {"code":0,...,"data":{}}. The game sees a
        #   non-ZIP body, falls back to parsing it as JSON, expects an ARRAY and
        #   logs:  LogJson: Error: Json Value of type 'Object' used as a 'Array'.
        #   ServerList therefore stays EMPTY, and LaunchWorld.min.cbc
        #   PerformLoginUseSdk does ServerList[0] ->
        #     Puerts: Error: invalid index 0, array length is 0
        #   The JS world object dies right there, so the game never even opens a
        #   net driver (shutdown log: HasNetDriver=false HasPendingNetGame=false)
        #   -> endless "entering world" spinner.
        #   Fix: hand back the AUTHENTIC bytes. We do not need the ZIP password -
        #   the client has it. Responses are cached to bypass\cache so this keeps
        #   working offline / if the real confserver disappears.
        # Must sit BEFORE the generic `"version" in low` branch below, which
        # would otherwise swallow /cb1/config/system_switch/version.
        #
        # 2026-10-17 (v3): the ZIP password was recovered (GkCA8b2ahJFw88ZRxkaz),
        # so make_local_configs.py rebuilds a byte-exact WinZip-AES serverlist
        # with Status=1 and no maintenance dialog. The real test servers were
        # wiped/closed on 2026-09-27, so proxying the REAL file just makes the
        # client show "测试已结束". Serve OUR rebuilt ZIP instead; fall back to
        # proxying the real one if the local file is missing.
        if low.startswith(("/cb1/config/compat_matrix/", "/cb1/config/system_switch/")):
            local = os.path.join(PROXY_CACHE, "local_configs",
                                 "compat_matrix.json" if "compat_matrix" in low else "system_switch.json")
            if os.path.exists(local):
                log(f"  -> 200 LOCAL rebuilt config ZIP {os.path.basename(local)}")
                self._serve_file(local, "application/json")
                return
            up_host = "eee-confserver.game.ruyi.cn"
            log(f"  -> proxy REAL config {self.path} from {up_host}:19030")
            _proxy_serve(self, up_host, 19030, True, self.path)
            return
        # ================= SDK LOGIN (cn-open.jx.ruyi.cn) =================
        # All of these are GET per NetAccount.cs / NetPlatform.cs.
        if "identity/status" in path:
            # RealNameManagerImpl.Query: data >= 18 -> OnEnterGame directly.
            # -100 would show the RealName (ID card) dialog — avoid.
            log("  -> 200 sdk identity/status (age 18)")
            self._reply({"code": 0, "msg": "ok", "data": 18})
            return
        if "identity/heartbeat" in path:
            # Only polled when underage (data<18) — harmless to answer ok.
            log("  -> 200 sdk identity/heartbeat ok")
            self._reply({"code": 0, "msg": "ok", "data": None})
            return
        if "query/login/before" in path or "query/login/after" in path:
            # OmsLoginAfter (NetPlatform.cs:189 GET) -> LoginAfter bean.
            # Empty surveys list: nothing to show after login.
            log("  -> 200 sdk oms query/login (no surveys)")
            self._reply({"code": 0, "msg": "ok", "data": {"surveys": []}})
            return
        if "device/servers" in path:
            # ApiImpl.Servers: JArray of Server. PerformLoginUES2 (LaunchWorld.min.cbc)
            # does servers[0] — an empty array crashes it ("invalid index 0, array
            # length is 0"). Return our local gate as the only server so the JS
            # login path connects to 127.0.0.1:10012 instead of the rotating
            # Tencent gate IPs.
            log("  -> 200 sdk device/servers [local gate]")
            self._reply({"code": 0, "msg": "ok", "data": [{
                "serverId": 1, "serverName": "local",
                "serverIp": "127.0.0.1", "serverPort": 10012,
                "extendParam": "",
            }]})
            return
        if path.endswith("/server") or "/server?" in self.path or "device/server" in path:
            # ApiImpl.Server(serverId) -> Server bean. The C++ SDK bridge only
            # serializes known fields (serverId, serverName, serverIp, serverPort,
            # extendParam). The JS login flow reads QUIC gate addresses from
            # extendParam as JSON (matching DefaultNzGame.ini ServerList Gate format).
            import json as _json
            gate_json = _json.dumps({
                "gate": ["127.0.0.1:25301", "127.0.0.1:25302"],
                "gateIp": "127.0.0.1",
                "gatePort": 25301,
                # H1 (00:52 brief): cheap probe - if the login flow reads any
                # of these for the DS/travel address, ClientTravel will change
                # from nz.X-0 to a real ip:port.
                "dsIp": "127.0.0.1", "dsPort": 7777,
                "dedicatedIp": "127.0.0.1", "dedicatedPort": 7777,
                "travelURL": "127.0.0.1:7777",
                "serverType": "Dedicated",
                "bUseDirectConnect": True,
            })
            log("  -> 200 sdk device/server (local gate, QUIC in extendParam)")
            self._reply({
                "code": 0, "msg": "ok",
                "data": {
                    "serverId": 1, "serverName": "local",
                    "serverIp": "127.0.0.1", "serverPort": 10012,
                    "extendParam": gate_json,
                },
            })
            return
        if "sms/login" in path:
            # SMS_MOBILE_CODE (send SMS code) — T=object, any data.
            log("  -> 200 sdk sms code sent (fake)")
            self._reply({"code": 0, "msg": "ok", "data": "ok"})
            return
        if "placard/list" in path or "activity/webviews" in path or "role/list" in path:
            # JArray / List<string> endpoints — empty arrays, no announcements.
            log(f"  -> 200 sdk list endpoint [] ({path})")
            self._reply({"code": 0, "msg": "ok", "data": []})
            return
        if "qrcode/generate" in path or "qrcode/status" in path or "qrcode/login" in path:
            # QR login flow (if the SDK falls back to QR): generate -> {uuid},
            # status -> string, login -> OpenData. Give a "not scanned" state
            # that keeps polling without erroring; user logs in via SMS instead.
            log(f"  -> 200 sdk qrcode ({path})")
            self._reply({"code": 0, "msg": "ok", "data": ""})
            return
        # ================= END SDK LOGIN =================
        if path.endswith("crl.crl") or path == "/crl" or path == "/crl.der":
            self._serve_file(CRL_FILE, "application/pkix-crl"); return
        if path.endswith("root.cer") or path.endswith("ca.crt") or path == "/issuer":
            self._serve_file(ROOT_CER, "application/pkix-cert"); return
        if path == "/ocsp":
            self.send_response(200); self.send_header("Content-Length", "0"); self.end_headers(); return
        if "changelog" in low:
            # GameLauncher changelog parser expects {releases:[{version,date(yyyy-MM-dd),changes,importantUpdate}]}
            log("  -> 200 changelog releases")
            self._reply({"releases": [{
                "version": LAUNCHER_VERSION, "date": "2026-10-01",
                "changes": ".", "importantUpdate": False,
            }]})
            return
        # --- BaseVersion.json / Version.json : launcher GameConfig + game NzUpdate ---
        # NOTE: must come BEFORE the generic "version" branch, but must NOT swallow
        # the launcher's own /launcher/official/config/version.json probe.
        if "baseversion.json" in low or "versionfile" in low:
            log("  -> 200 BaseVersion/versionfile payload")
            self._reply(base_version_payload())
            return
        # --- launcher self-update probe: /cb1/launcher/official/config/version.json ---
        if "launcher" in low and "version" in low:
            log("  -> 200 launcher version probe")
            self._reply(launcher_version_payload())
            return
        if "version" in low or "files.json" in low:
            # filesEndpoint: /basepackage/WindowsClient/{version}/files.json
            if "files.json" in low:
                # Launcher's manifest parser (GameLauncher.exe ~0x15b4c0) requires a
                # BARE JSON array of {remoteName, md5, fileSize} objects — an object
                # wrapper fails with error 203 "期望JSON数组格式". Empty array = no
                # files to download/verify → InGame_Pre_Verifying passes.
                log("  -> 200 files.json (bare empty array)")
                body = b"[]"
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            log("  -> 200 version payload (v0)")
            self._reply(version_payloads()[0])
            return
        # Catch-all (incl. SDK GETs we haven't mapped) — both "msg" and
        # "message" so OkHttpRsp-based SDK calls and launcher probes pass.
        log("  -> 200 generic ok")
        self._reply({"code": 0, "msg": "ok", "message": "ok", "data": {}})

    def log_message(self, fmt, *args):
        pass


class TLSHTTPServer(ThreadingHTTPServer):
    """Accepts raw, peeks the ClientHello for the log (so we can see what the
    client offers when the handshake fails), then wraps manually."""
    daemon_threads = True
    sslctx = None

    def get_request(self):
        conn, addr = self.socket.accept()
        # Peek the ClientHello without consuming — enough for diagnostics.
        try:
            first = conn.recv(1024, socket.MSG_PEEK)
            if first:
                log(f"TLS RX peek ({addr[0]}): {first[:96].hex()}")
        except Exception as e:
            log(f"peek failed: {e!r}")
        try:
            tlsconn = self.sslctx.wrap_socket(conn, server_side=True)
        except ssl.SSLError as e:
            log(f"TLS HANDSHAKE FAILED ({addr[0]}): {e!r}")
            try:
                conn.close()
            except OSError:
                pass
            # Raise a benign OSError — _handle_request_noblock logs/handles it
            # without a traceback storm.
            raise OSError("tls handshake failed") from None
        return tlsconn, addr


def make_https(port):
    httpsd = TLSHTTPServer(("127.0.0.1", port), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(SERVER_CHAIN, SERVER_KEY)
    ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    # Accept legacy clients too — if the game's .NET bridge offers TLS 1.0/1.1
    # (old Mono/CoreCLR defaults), a TLS1.2-minimum server kills the handshake
    # with "protocol version" and the SDK only sees a transport error.
    ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
    httpsd.sslctx = ctx
    log(f"HTTPS listening on 127.0.0.1:{port}")
    return httpsd


def main():
    servers = []
    httpd = ThreadingHTTPServer(("127.0.0.1", 80), Handler)
    httpd.daemon_threads = True
    log(f"HTTP  listening on 127.0.0.1:80 (CRL/OCSP/generic)")
    servers.append(httpd)

    confd = ThreadingHTTPServer(("127.0.0.1", 9080), Handler)  # confserver.tpo...:9080 is http://
    confd.daemon_threads = True
    log(f"HTTP  listening on 127.0.0.1:9080 (confserver)")
    servers.append(confd)

    for p in (19030, 443):
        try:
            servers.append(make_https(p))
        except OSError as e:
            log(f"FAILED to bind HTTPS :{p}: {e}")

    import threading
    for s in servers:
        threading.Thread(target=s.serve_forever, daemon=True).start()
    log("v2 fake server up. Ctrl+C to stop.")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
