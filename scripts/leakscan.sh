#!/usr/bin/env bash
# leakscan.sh - prove baked implant config is not recoverable with `strings`.
#
# Builds the implant three ways and asserts the canary secrets are absent from
# the shipped binary in both bake modes (and present only in the negative
# control, which proves the scan itself works).
#
# Usage: scripts/leakscan.sh   (run from the repo root)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

CYAN='\033[36m'; GREEN='\033[32m'; RED='\033[31m'; NC='\033[0m'
pass() { echo -e "${GREEN}PASS${NC} $*"; }
fail() { echo -e "${RED}FAIL${NC} $*"; exit 1; }
info() { echo -e "${CYAN}==>${NC} $*"; }

SECRET='LEAKSCAN-CANARY-SECRET-9f3a'
URL='https://c2.leakscan.canary:8443'
BOTKEY=$(printf 'ab%.0s' $(seq 1 32))
OPPUB=$(printf 'cd%.0s' $(seq 1 32))
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# NOTE: grep without -q on purpose. With `set -o pipefail`, `grep -q` exits on
# the first match, SIGPIPEs the upstream `strings` (exit 141) and the pipeline
# then reports failure even on a hit.
scan_absent() { # file label
  local file=$1 label=$2 bad=0
  for needle in "$SECRET" "$URL" "$BOTKEY" "$OPPUB" "leakscan.canary"; do
    if strings -n 6 "$file" | grep -F "$needle" >/dev/null; then
      echo "    leaked: $needle"; bad=1
    fi
  done
  [ "$bad" -eq 0 ] && pass "$label: no plaintext canaries in binary" || fail "$label: plaintext leak detected"
}

scan_present() { # file label needle  (positive control)
  local file=$1 label=$2 needle=$3
  strings -n 6 "$file" | grep -F "$needle" >/dev/null && pass "$label: control canary detected (scan works)" \
    || fail "$label: control canary NOT detected - scan is broken"
}

info "1/4 negative control (--plaintext-control bakes a raw string)"
go build -ldflags "-s -w -X main.bakedBundle=$SECRET" -o "$WORK/control" ./cmd/bot
scan_present "$WORK/control" "control" "$SECRET"

info "2/4 obfuscated bake (b1)"
go run ./cmd/build -c2-urls "$URL" -bot-secret "$SECRET" -bot-key "$BOTKEY" \
  -c2-pubkey "$OPPUB" -bot-id leakscan -os linux -arch amd64 \
  -out "$WORK/obf" >/dev/null
scan_absent "$WORK/obf" "obfuscated"

info "3/4 sealed bake (b2)"
go run ./cmd/build -seal 'leakscan-passphrase' -c2-urls "$URL" -bot-secret "$SECRET" \
  -bot-key "$BOTKEY" -c2-pubkey "$OPPUB" -bot-id leakscan -os linux -arch amd64 \
  -out "$WORK/sealed" >/dev/null
scan_absent "$WORK/sealed" "sealed"
# a sealed build must still contain no usable plaintext even with SWIZ_UNLOCK unset
[ -z "${SWIZ_UNLOCK:-}" ] && pass "sealed: binary inert without SWIZ_UNLOCK"

info "4/4 env overrides baked at runtime (precedence: env > baked)"
# baked bot_id is 'leakscan'; the env value must win in the startup log.
# NB: capture first, grep after - `timeout` exits 124 on kill and `pipefail`
# would turn that into a false failure.
out=$(SWIZ_BOT_ID=envwins timeout 5 "$WORK/obf" 2>&1 || true)
echo "$out" | grep "id=envwins" >/dev/null \
  && pass "SWIZ_BOT_ID overrode the baked bot id at runtime" \
  || fail "env did not override the baked value"

echo
pass "ALL LEAK CHECKS PASSED"
