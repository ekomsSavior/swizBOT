# Verification status

What has actually been **executed** versus what only compiles and is unit
tested. Kept honest on purpose: a thing that builds is not a thing that
runs.

Last updated 2026-09-10 (main).

## Live-verified

| area | how | result |
|------|-----|--------|
| Linux implant end to end | boot C2, bake implant, `exec` command | registered, sealed AEAD checkin, result `success` |
| Obfuscated baked config (b1) | `make leakscan` | no string-recoverable secrets |
| Sealed baked config (b2) | `make leakscan` + live run | inert without `SWIZ_UNLOCK`; loads with it |
| DNS fallback layer | local stub, HTTPS endpoint dead, command published as TXT `swiz1:<b64>` | implant opened + executed the command over DNS |
| Windows implant (Wine) | Wine 10 + Xvfb, host C2 | registered (`windows/amd64`), sealed channel active, `exec` returned `WIN-EXEC-OK` |
| Windows GDI screenshot (Wine) | `screenshot` command | valid PNG, 1280x1024 |
| Windows registry persistence (Wine) | run implant | `HKCU\...\Run` -> `swizBOT` value written |
| Transport manager | unit tests (controllable clock) | failover, probation, recovery, backoff cap, ordering |

## Compiled + unit-tested only (not live-fired here)

- **Telegram dead-drop layer** — needs a real bot token + chat.
- **P2P LAN discovery** — needs a real multi-host LAN.
- **SMB / USB / network-share vectors** and **scheduled-task persistence** —
  need a real Windows host; Wine has no SMB server and no `schtasks`.
- **Stager** — emulator round-trips + nasm byte parity only; not run on
  Windows hardware.

## Deliberately not run

- **Worm spread loop** — not executed (sandbox policy).

## Reproducing

```bash
make vet && make test          # static + unit
make leakscan                  # baked-config leak scan (with negative control)
python3 stager/encoder.py --selftest
```

DNS-fallback live test: stand up a local DNS responder on `127.0.0.1:53`
that answers TXT `swiz1:<base64url(sealed frame)>` for a test zone and
forwards other queries upstream, point `/etc/resolv.conf` at it (restore
after), set `SWIZ_DNS_DOMAIN`, and run the implant with an unreachable
`SWIZ_C2_URLS`. The command must arrive over DNS.

Windows-under-Wine: `WINEPREFIX=... xvfb-run -a wine ./swizbot-bot.exe`
with a Linux C2 as the endpoint (`SWIZ_C2_URLS`/baked), then `exec` /
`screenshot` and a registry check.
