# AmneziaWG Packet Signature Generator

A Rust CLI tool that captures TLS ClientHello packets and outputs their signatures in AmneziaWG format (`<b 0xHEX>`) for use as junk packet obfuscation.

## Requirements

- **Wireshark/tshark** installed and in PATH
- **Administrator/root privileges** for packet capture

### Installation

**Windows:** Install [Wireshark](https://www.wireshark.org/download.html), ensure `tshark.exe` is in PATH

**Linux:**
```bash
sudo apt install tshark
```

**macOS:**
```bash
brew install wireshark
```

## Build

```bash
cargo build --release
```

## Usage

```
awg-sig-gen [OPTIONS]

Options:
  -i, --interface <NAME>   Network interface to capture on (required)
  -c, --count <N>          Number of signatures to capture [default: 5]
  -o, --output <FILE>      Output file path [default: signatures.txt]
  -d, --domain <PATTERN>   Domain filter regex [default: \.ru$]
  -t, --timeout <SECS>     Capture timeout in seconds [default: 60]
  -l, --list-interfaces    List available network interfaces
  -v, --verbose            Enable verbose output
  -h, --help               Print help
  -V, --version            Print version
```

### Examples

List available interfaces:
```bash
awg-sig-gen -l
```

Capture 5 signatures from Ethernet interface:
```powershell
# Windows (Admin PowerShell)
.\awg-sig-gen.exe -i "Ethernet" -c 5 -o signatures.txt
```

```bash
# Linux/macOS
sudo ./awg-sig-gen -i eth0 -c 5 -o signatures.txt
```

Capture with custom domain filter and verbose output:
```bash
awg-sig-gen -i eth0 -d "\.ru$|\.by$" -c 10 -v
```

## Output Format

Signatures are written one per line in AmneziaWG format:

```
<b 0x1603010200010002010303...>
<b 0x160303012a0100012603...>
<b 0x1603010188010001840303...>
```

Each signature starts with `16 03` (TLS handshake record header).

## How It Works

1. Spawns `tshark` to capture TLS ClientHello packets on port 443
2. Filters packets by SNI (Server Name Indication) matching the domain pattern
3. Extracts TCP payload and validates it's a valid TLS record
4. Formats as AmneziaWG junk packet signature

## License

MIT
