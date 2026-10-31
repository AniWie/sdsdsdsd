@echo off
rem ============================================================
rem  WeiMianYe - local bypass launcher
rem
rem  What it does:
rem    1. kills stale fake_server_v2 / gate_server / quic_capture
rem    2. gate server IP aliases (UAC)
rem    3. portproxy rules (UAC)
rem    4. hosts entries (UAC) - all domains incl. SDK login
rem    5. regenerates the leaf cert (SAN includes cn-open.jx.ruyi.cn)
rem    6. rebuilds the local serverlist ZIP (Status=1, local gate)
rem    7. PURGES the game's config cache (critical, see below)
rem    8. clears old logs
rem    9. raises fake server + gate server + QUIC capture
rem   10. HARD-WAITS for every port before launching the game
rem   11. launches the game in its own visible console (run_game.cmd)
rem
rem  NOTE: pure ASCII on purpose. cmd parses batch files in the OEM
rem  codepage (cp866 on a RU locale), so UTF-8 Russian text here turns
rem  into mojibake before chcp ever runs.
rem ============================================================
chcp 65001 >nul
title WeiMianYe bypass

rem --- 1. kill stale servers -------------------------------------------
powershell -NoProfile -Command ^
  "Get-CimInstance Win32_Process -Filter \"Name='python.exe'\" | Where-Object { $_.CommandLine -like '*fake_server_v2*' -or $_.CommandLine -like '*gate_server*' -or $_.CommandLine -like '*quic_capture*' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }" >nul 2>&1
timeout /t 1 /nobreak >nul

rem --- 2. gate server IP aliases (UAC) ---------------------------------
echo [bypass] Adding gate server IP aliases (needs Admin)...
powershell -NoProfile -Command ^
  "Start-Process powershell -Verb RunAs -Wait -ArgumentList '-NoProfile -File D:\Games\WeiMianYe\bypass\add_gate_aliases.ps1'" >nul 2>&1

rem --- 3. portproxy rules (persistent, refreshed for new IPs) ----------
powershell -NoProfile -Command ^
  "Start-Process powershell -Verb RunAs -Wait -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File D:\Games\WeiMianYe\bypass\add_gate_portproxy.ps1'" >nul 2>&1

rem --- 4. hosts (adds cn-open.jx.ruyi.cn for SDK login) ----------------
echo [bypass] Updating hosts (SDK login domain)...
powershell -NoProfile -Command ^
  "Start-Process powershell -Verb RunAs -Wait -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File D:\Games\WeiMianYe\bypass\add_hosts.ps1'" >nul 2>&1

rem --- 5. regenerate leaf cert -----------------------------------------
echo [bypass] Regenerating leaf cert with SDK login SAN...
python -I -X utf8 "D:\Games\WeiMianYe\bypass\gen_chain.py" >nul 2>&1

rem --- 6. rebuild local configs ----------------------------------------
rem serverlist.json / system_switch.json are WinZip-AES-256 ZIPs on the real
rem confserver. Password recovered 2026-10-17: GkCA8b2ahJFw88ZRxkaz (crack3.py).
rem The real one carries Status=3 + the "test has ended" dialog, so we rebuild
rem it with Status=1 and a local gate.
echo [bypass] Rebuilding local serverlist config...
python -I -X utf8 "D:\Games\WeiMianYe\bypass\make_local_configs.py" "127.0.0.1:25301,127.0.0.1:25302" >nul 2>&1

rem --- 7. PURGE the game's config cache --------------------------------
rem CRITICAL: the game caches compat_matrix / system_switch under
rem HotfixDir\config\ and only compares the version number (which we proxy
rem from the real server). Without this purge it loads the OLD real ZIP with
rem Status=3 and the maintenance dialog comes back.
echo [bypass] Purging game config cache...
powershell -NoProfile -Command ^
  "$c='E:\Games\Games\WeiMianYeGame\Game\Saved\PersistentDownloadDir\HotfixDir\config'; if (Test-Path $c) { Get-ChildItem $c -Recurse -File | Where-Object { $_.FullName -notlike '*versionfile*' } | ForEach-Object { Remove-Item $_.FullName -Force } }" >nul 2>&1

rem --- 8. clear old logs so runs don't mix -----------------------------
if not exist "D:\Games\WeiMianYe\bypass\logs" mkdir "D:\Games\WeiMianYe\bypass\logs"
del /q "D:\Games\WeiMianYe\bypass\logs\activation.log" 2>nul
del /q "D:\Games\WeiMianYe\bypass\logs\gate.log" 2>nul
del /q "D:\Games\WeiMianYe\bypass\logs\quic.log" 2>nul
del /q "D:\Games\WeiMianYe\bypass\logs\game_launch.log" 2>nul
del /q "D:\Games\WeiMianYe\bypass\logs\game_launch_dec.log" 2>nul
del /q "D:\Games\WeiMianYe\bypass\logs\fake_stdout.log" 2>nul
del /q "D:\Games\WeiMianYe\bypass\logs\gate_stdout.log" 2>nul
del /q "D:\Games\WeiMianYe\bypass\logs\quic_stdout.log" 2>nul
if exist "D:\Games\WeiMianYe\bypass\logs\quic_pkts" rmdir /s /q "D:\Games\WeiMianYe\bypass\logs\quic_pkts"

rem --- 9. raise the servers via wrapper scripts ------------------------
rem INCIDENT 2026-10-19 01:49: inline redirects "1>> log 2>> log" inside
rem start cmd /c "..." silently failed after killing the old processes - the
rem new python died instantly and wrote NOTHING to the log, which looked like
rem an unsolvable mystery. Wrapper .cmd files are reliable: the window stays
rem open if it dies, and the exit code is appended to the log.
echo [bypass] Starting fake server v2...
start "WeiMianYe fake server" /min cmd /c "D:\Games\WeiMianYe\bypass\_srv_fake.cmd"

echo [bypass] Starting gate server...
start "WeiMianYe gate server" /min cmd /c "D:\Games\WeiMianYe\bypass\_srv_gate.cmd"

rem serverlist points Gate=127.0.0.1:25301/25302, so the game's Go stack
rem (asyncquiclink.go) dials US. Log: logs\quic.log + logs\quic_pkts\*.bin
echo [bypass] Starting QUIC gate capture (UDP 25301/25302)...
start "WeiMianYe quic capture" /min cmd /c "D:\Games\WeiMianYe\bypass\_srv_quic.cmd"

rem --- 10. HARD-WAIT for every port ------------------------------------
rem INCIDENT 2026-10-18 00:17: the game was launched while the servers were
rem DEAD. The SDK got connection refused and showed
rem "An error occurred while sending the request" with code -1. That looked like
rem a new bug but was simply the servers never having come up.
rem
rem TRAP: netsh portproxy (iphlpsvc, pid ~5412) listens on the REAL IPs
rem (42.81.194.29:80, 43.159.233.119:443, 43.159.233.192:10012 ...), so a
rem plain "is port N listening?" check passes even when python is dead.
rem The only honest marker is LocalAddress == 127.0.0.1:
rem   fake_server_v2 : 127.0.0.1:80, 443, 9080, 19030
rem   gate_server    : 127.0.0.1:10012, 10013, 10014, 10015
set /a tries=0
:waitloop
powershell -NoProfile -Command ^
  "$need=80,443,9080,19030,10012,10013; $miss=@(); foreach($p in $need){ $c=Get-NetTCPConnection -LocalAddress 127.0.0.1 -LocalPort $p -State Listen -ErrorAction SilentlyContinue; if(-not $c){ $miss+=$p } }; if($miss.Count -gt 0){ Write-Host ('  waiting for 127.0.0.1:' + ($miss -join ',')) ; exit 1 } else { exit 0 }"
if %errorlevel%==0 goto ports_ok
set /a tries+=1
if %tries% geq 40 goto ports_fail
timeout /t 1 /nobreak >nul
goto waitloop

:ports_fail
echo.
echo ============================================================
echo  [bypass] ERROR: the bypass servers did NOT come up in 40 s.
echo  [bypass] NOT launching the game - otherwise you get
echo           "An error occurred while sending the request" (code -1),
echo           exactly like on 2026-10-18 00:17.
echo.
echo  [bypass] What to check:
echo    1. Did the "WeiMianYe fake server" / "gate server" windows open?
echo       If they closed instantly there is an error inside them -
echo       most often the port is taken or 80/443 needs elevation.
echo    2. Taken ports:  netstat -ano ^| findstr ":80 :443 :19030"
echo    3. Log tails:    type D:\Games\WeiMianYe\bypass\logs\fake_stdout.log
echo                     type D:\Games\WeiMianYe\bypass\logs\gate_stdout.log
echo ============================================================
pause >nul
exit /b 1

:ports_ok
echo.
echo [bypass] All ports listening: fake (80/443/9080/19030) + gate (10012/10013) + QUIC (25301/25302 UDP)
echo [bypass] SDK login: cn-open.jx.ruyi.cn -^> 127.0.0.1 (any phone + any SMS code)
echo [bypass] serverlist: Status=1, Gate=127.0.0.1:25301/25302 (maintenance dialog removed)
echo [bypass] Launching the game in its own console...
timeout /t 1 /nobreak >nul

rem --- 11. launch the game in a VISIBLE console -------------------------
rem The console is not minimised: the UE log streams into it live
rem (-log -stdout -FullStdOutLogOutput), so a crash shows its last line.
start "WeiMianYe game console" cmd /c "D:\Games\WeiMianYe\bypass\run_game.cmd"

echo.
echo [bypass] Game launched. These windows should stay open:
echo   - "WeiMianYe fake server"   (HTTP/HTTPS 80/443/9080/19030)
echo   - "WeiMianYe gate server"   (TCP 10012-10015)
echo   - "WeiMianYe quic capture"  (UDP 25301/25302)
echo   - "WeiMianYe game console"  (the game itself + log)
echo.
echo [bypass] Logs:
echo   activation.log    - HTTP(S) requests from the game to the fake server
echo   gate.log          - TCP 10012-10015
echo   quic.log          - UDP 25301/25302 (gate traffic)
echo   game_launch.log   - UE log (XOR encrypted)
echo   game_launch_dec.log - decrypted UE log (appears after the game exits)
echo.
echo [bypass] This window can be closed - the servers live in their own.
pause >nul
