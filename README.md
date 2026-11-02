# PortPeek

A lightweight, multithreaded TCP port scanner written in Python. It prints
results in real time and shows the service name and version banner of every
open port.

## Features
- Real-time output as each port is checked
- Reports **open**, **closed**, and **filtered** ports
- Service name and version/banner detection (SSH, FTP, SMTP, HTTP/HTTPS, ...)
- Flexible port selection (`22,80,443` or `1-65535`)
- Adjustable threads and timeout
- Save results to a file
- Standard library only: no dependencies

## Requirements
- Python 3.8+
- Linux, macOS, or Windows (tested on Kali Linux)

## Installation

```bash
git clone https://github.com/YOUR-USERNAME/portpeek.git
cd portpeek
chmod +x portpeek.py
```

## Usage

```bash
python3 portpeek.py <target> [options]
```

Examples:

```bash
python3 portpeek.py 127.0.0.1
python3 portpeek.py 192.168.1.10 -p 1-65535 -w 300
python3 portpeek.py 192.168.1.10 -p 22,80,443 --show-closed
python3 portpeek.py 192.168.1.10 -o results.txt
```

Sample output:

```
PORT   STATE     SERVICE       VERSION / BANNER
22     open      ssh           SSH-2.0-OpenSSH_9.6p1 Debian-4
80     open      http          HTTP - Apache/2.4.58 (Debian)

Done in 1.84s - 2 open, 1020 closed, 2 filtered
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-p`, `--ports` | Ports to scan (`80`, `22,80`, `1-1024`) | `1-1024` |
| `-t`, `--timeout` | Seconds to wait per port | `1.0` |
| `-w`, `--workers` | Parallel threads | `100` |
| `--show-closed` | Also print closed/filtered ports | off |
| `-o`, `--output` | Save open ports to a file | none |

## How it works
For each port, PortPeek attempts a TCP connection. A completed connection means
**open**; a refusal means **closed**; no reply means **filtered** (usually a
firewall). On open ports it reads the service's greeting banner, or sends a
small HTTP `HEAD` request on web ports, to identify the software and version.

## Disclaimer
This tool is for education and authorized security testing only. Scan only
systems you own or have **written permission** to test. The author is not
responsible for misuse.

## License
MIT
