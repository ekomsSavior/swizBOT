# LAN peer discovery (P2P)

The implant can learn additional C2 endpoints from other implants on
the same LAN. This is an auxiliary discovery layer; the primary
endpoints from SWIZ_C2_URLS always stay first in the rotation.

## Enable

```
SWIZ_P2P=1 SWIZ_PEER_PORT=31337 ./swizbot-bot-linux
```

Every participating implant:

- listens on UDP :31337 (SWIZ_PEER_PORT) for `SWIZC2 <url> [<url>...]`
  announcements;
- answers a peer with its own endpoint list;
- broadcasts its own list to the /24 directed broadcast every 60
  seconds.

Learned endpoints are merged into the client rotation (deduplicated,
capped at 32). Discovery is plaintext and unauthenticated: it is a
fallback for finding a C2 after primary domains are gone, not a
security boundary. On networks where you do not want the implant to
answer discovery traffic, leave SWIZ_P2P unset.
