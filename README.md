# swizBOT
modular, shellcode-driven botnet that implements JAKESWIZ aka 0xXyc techniques

#let us gather here today to honor our fellow researcher JAKESWIZ aka 0xXyc the great the GOAT. 
**Blessed be our swizBOT**

Why This Is Revolutionary (Jake's Contribution)

Without Jake's research, building swizBOT would require:

    Hardcoding Windows API addresses that break on every update

    Using bloated msfvenom payloads that are signatured

    Failing on ARM Windows (Surface Pro X, Macs)

    No way to bypass ASLR reliably

With Jake's techniques:

    One stager works on x86, x64, and ARM Windows

    XOR encoding bypasses static AV signatures

    PEB walking works on every Windows version from 7 to 11

    Botnet survives and spreads everywhere

