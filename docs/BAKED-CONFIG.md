# Baked config & OPSEC

`cmd/build` compiles implant configuration straight into the binary, so a
field deployment is one artifact instead of an env-var bundle. This note
covers how that config is protected on disk and on the wire, what it does
and does not guarantee, and how to verify it.

## The problem it fixes

Earlier builds injected each value as its own plaintext symbol:

```
-ldflags "-X main.bakedC2URLs=https://c2.example:8443 \
          -X main.bakedBotSecret=s3cret \
          -X main.bakedBotKey=<implant-priv-hex>"
```

`-ldflags -X` assigns a Go string variable, and string data lives verbatim
in the binary. A single `strings` pass recovered the C2 endpoints, the
shared bot secret and the implant private key from the shipped artifact —
no reverse engineering required. That is convenience, not OPSEC.

## What we do now

All baked values are packed into one opaque token (`internal/bakepack`) and
injected as a single string, `main.bakedBundle`:

| Mode | Token | Mechanism | Guarantee |
|------|-------|-----------|-----------|
| obfuscated (default) | `b1.<base64url>` | `salt(16) ‖ json XOR SHA-256(seed‖salt‖ctr)` | secrets are not present as readable strings in the binary |
| sealed (`-seal PASS`) | `b2.<base64url>` | `salt(16) ‖ nonce(12) ‖ AES-256-GCM(json)`, key = PBKDF2-HMAC-SHA256(PASS, salt, 210k) | **authenticated encryption**: the binary alone discloses nothing and is inert without the passphrase |

### Obfuscated (b1)

Defeats casual triage, `strings`/`grep`, AV/EDR static string scanners and
config hunters. It is **obfuscation, not encryption**: someone who reverses
the token format can recover the values. Use it when you only need the
artifact to not hand over its config on a plate.

### Sealed (b2)

Real AEAD under an operator passphrase that is supplied out-of-band at
runtime via `SWIZ_UNLOCK`. The binary embeds only ciphertext + KDF salt, so
a recovered artifact is useless without the passphrase. A wrong or missing
`SWIZ_UNLOCK` fails authentication — the implant does **not** silently fall
back to a baked secret it could not decrypt; it logs and continues on
env/defaults. This is the mode to use for real OPSEC.

> Note: no self-contained artifact can hide a secret from someone who holds
> both the binary *and* the runtime secret. b2 moves the secret out of the
> binary and into operator custody; it does not put it nowhere.

## Precedence

```
env (SWIZ_*)  >  baked (token)  >  built-in default
```

Env always wins, so an operator can override any baked value without a
rebuild. A sealed bundle that cannot be unlocked simply contributes nothing.

## Building

```bash
# obfuscated (default)
go run ./cmd/build -c2-urls https://c2.example:8443 \
  -bot-secret s3cret -bot-key <implant-hex> -c2-pubkey <op-hex>

# sealed -> zero-leak; set SWIZ_UNLOCK at runtime
go run ./cmd/build -seal 'correct horse battery staple' \
  -c2-urls https://c2.example:8443 \
  -bot-secret s3cret -bot-key <implant-hex> -c2-pubkey <op-hex>
```

Baking secrets without `-seal` prints a warning.

## Verifying

`make leakscan` (or `scripts/leakscan.sh`) builds the implant three ways and
asserts the canary secrets are absent from the binary in both bake modes,
using a deliberate plaintext negative control to prove the scanner works.

```bash
$ make leakscan
==> 1/4 negative control ... PASS control: control canary detected (scan works)
==> 2/4 obfuscated bake (b1) ... PASS obfuscated: no plaintext canaries in binary
==> 3/4 sealed bake (b2) ... PASS sealed: no plaintext canaries in binary
==> 4/4 env still overrides baked ... PASS
ALL LEAK CHECKS PASSED
```

Unit coverage lives in `internal/bakepack/bakepack_test.go`: round-trip for
both modes, passphrase required/wrong/tamper rejection, and a
plaintext-absence regression guard.
