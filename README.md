# 🔍 Packet Sniffer - Network Analysis Tool

A Python-based packet sniffer for capturing and analyzing network traffic using raw sockets.

## ⚠️ Legal Warning

**This tool must only be used on networks where you have explicit authorization.**

Intercepting communications without permission is illegal in most jurisdictions. Use only on:
- Your own networks
- Educational environments with proper authorization
- Penetration testing engagements with written permission

## 🚀 Features (Current Phase)

### Phase 1.1 - Basic Configuration ✅
- Cross-platform support (Windows/Linux/macOS)
- Automatic OS detection
- Administrator/root privilege verification
- System information display
- Legal compliance warning

### Phase 1.2 - Basic Packet Capture ✅
- Raw socket creation
- Promiscuous mode (Windows)
- Packet capture loop
- Hexadecimal packet display
- Configurable capture count
- Clean resource management

### Phase 1.3 - Network Headers Parsing ✅
- Ethernet header parsing (MAC addresses, protocol type)
- IP header parsing (IPv4, source/dest IP, TTL, protocol)
- TCP header parsing (ports, sequence, acknowledgment, flags)
- UDP header parsing (ports, length)
- ICMP header parsing (type, code)
- Human-readable packet display
- Payload preview

### Phase 2.1 - Filters and CLI Arguments ✅
- Command-line argument parsing (argparse)
- Protocol filtering (TCP, UDP, ICMP)
- Source IP filtering
- Destination IP filtering  
- Port filtering (source or destination)
- Configurable packet count
- **Endless mode** (capture until Ctrl+C with `-c 0`)
- Verbose mode for debugging
- Real-time statistics (packets by protocol, filtered count)
- **Port usage analysis** (Wireshark-style table)
- **Reverse DNS lookup** for all packets (public IPs)
- **Hostname discovery** (identify websites by IP)
- Comprehensive help and usage examples

### Phase 2.2 - Enhanced UI ✅
- **Colored terminal output** with colorama
- Protocol color-coding (TCP=Green, UDP=Blue, ICMP=Yellow)
- IP addresses highlighted in yellow
- Service names in cyan
- Error messages in red
- Enhanced visual formatting with styled headers
- Improved readability of all output sections
- Real-time packet display with color-coded protocol indicators

## 📋 Requirements

- Python 3.7+
- Administrator/root privileges
- Dependencies:
  - `colorama` (for colored output)
  - Standard library: `socket`, `struct`, `platform`, `sys`, `os`, `argparse`

## 🔧 Installation

1. Clone or download this repository
2. Install required dependencies:
   ```bash
   pip install colorama
   ```
   Or create a virtual environment:
   ```bash
   python -m venv .venv
   .venv\Scripts\activate  # Windows
   pip install colorama
   ```

## 💻 Usage

### Basic Usage

**Windows (Run PowerShell as Administrator):**
```powershell
# Capture 10 packets (default)
python main.py

# Capture 50 packets
python main.py -c 50

# Endless mode - capture until Ctrl+C
python main.py -c 0

# Show help and all options
python main.py --help
```

### Linux/macOS

```bash
# Capture with default settings
sudo python3 main.py

# Capture 30 packets
sudo python3 main.py -c 30
```

### Filtering Options

```powershell
# Capture only TCP packets
python main.py -p tcp

# Capture only UDP traffic on port 53 (DNS)
python main.py -p udp --port 53

# Capture packets from specific source IP
python main.py --src-ip 192.168.1.100

# Capture packets to specific destination IP
python main.py --dest-ip 8.8.8.8

# Capture 20 TCP packets on port 80 (HTTP)
python main.py -p tcp --port 80 -c 20

# Endless HTTPS monitoring
python main.py -c 0 -p tcp --port 443

# Verbose mode (show parsing errors)
python main.py -v
```

### Command-Line Arguments

| Argument | Short | Description | Example |
|----------|-------|-------------|---------|
| `--count` | `-c` | Number of packets to capture (0 = endless) | `-c 50` or `-c 0` |
| `--protocol` | `-p` | Filter by protocol (tcp/udp/icmp) | `-p tcp` |
| `--src-ip` | | Filter by source IP address | `--src-ip 192.168.1.1` |
| `--dest-ip` | | Filter by destination IP address | `--dest-ip 8.8.8.8` |
| `--port` | | Filter by port (source or dest) | `--port 443` |
| `--verbose` | `-v` | Show parsing errors | `-v` |
| `--help` | `-h` | Show help message | `-h` |

## 📊 Current Capabilities

- Captures raw network packets
- Displays packets in human-readable format
- Parses Ethernet headers (Linux/macOS)
- Parses IP headers (version, TTL, protocol, IPs)
- Parses TCP headers (ports, flags, sequence numbers)
- Parses UDP headers (ports, length)
- Parses ICMP headers (type, code)
- Shows payload preview
- Clean interruption handling (Ctrl+C)

## 🎯 Roadmap

### Phase 1.3 - Network Headers Parsing (Next)
- Parse Ethernet headers
- Parse IP headers
- Parse TCP/UDP headers
- Display human-readable packet information

### Phase 2 - Advanced Features (Planned)
- Protocol filtering (TCP, UDP, ICMP)
- IP address filtering
- Port filtering
- Command-line arguments
- Colored output

### Phase 2.3 - Export Features (Planned)
- Export to JSON format
- Export to text log files
- Timestamp tracking
- Session recording

### Phase 3 - Storage and Analysis (Planned)
- Export to text/JSON format
- Traffic statistics
- Top talkers analysis

### Phase 4 - Executable (Planned)
- Portable Windows executable (PyInstaller)
- No Python installation required
- Automatic privilege elevation

## 🛠️ Technical Details

### Socket Configuration

**Windows:**
- Protocol: `IPPROTO_IP`
- Socket type: `SOCK_RAW`
- Promiscuous mode: `SIO_RCVALL`

**Linux:**
- Protocol: `AF_PACKET`
- Captures all protocols (Layer 2)

**macOS:**
- Protocol: `IPPROTO_IP`
- Requires root privileges

## 🐛 Troubleshooting

### "Permission denied" error
- **Windows:** Run PowerShell/CMD as Administrator
- **Linux/macOS:** Use `sudo` to run with root privileges

### No packets captured
- Verify administrator/root privileges
- Check firewall settings
- Ensure network traffic is active (ping, browse web)

### Socket creation fails
- Antivirus may block raw socket creation
- Try temporarily disabling antivirus (at your own risk)
- Verify no other packet capture tool is running

## 📝 Project Structure

```
Packet_Sniffer/
├── main.py           # Main application file
└── README.md         # This file
```

## 👨‍💻 Development

**Author:** Mathieu  
**Date:** November 2025  
**Purpose:** Cybersecurity portfolio project

## 📄 License

This is an educational project. Use responsibly and legally.

---

**Current Status:** Phase 2.2 Complete - Enhanced UI with Colors ✅

**Next Phase:** Phase 2.3 - Export Features (JSON, text files, timestamps)
