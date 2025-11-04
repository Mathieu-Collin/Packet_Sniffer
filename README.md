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

### Phase 2.3 - Export Features ✅
- **JSON export** with full packet details and metadata
- **Text export** with human-readable format
- **Timestamp tracking** for each captured packet (ISO 8601 format)
- Automatic output directory management
- Export includes:
  - Capture metadata (date, OS, filters, statistics)
  - Complete packet information (headers, ports, hostnames)
  - Transport layer details (TCP flags, UDP length, ICMP type)
- Configurable output directory
- Export on-demand (opt-in with flags)

## 📋 Requirements

- Python 3.7+
- Administrator/root privileges
- Dependencies:
  - `colorama` (for colored output)
  - Standard library: `socket`, `struct`, `platform`, `sys`, `os`, `argparse`, `json`, `datetime`, `pathlib`

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

### Export Features

```powershell
# Capture 100 packets and export to JSON
python main.py -c 100 --export-json

# Capture 50 packets and export to text file
python main.py -c 50 --export-txt

# Export to both JSON and text formats
python main.py -c 100 --export-json --export-txt

# Export with custom output directory
python main.py -c 50 --export-json --output-dir logs

# Endless mode with JSON export (stop with Ctrl+C)
python main.py -c 0 --export-json

# Capture HTTPS traffic and export
python main.py -p tcp --port 443 -c 200 --export-json --export-txt
```

**Export files naming convention:**
- JSON: `capture_YYYYMMDD_HHMMSS.json`
- Text: `capture_YYYYMMDD_HHMMSS.txt`
- Default location: `captures/` directory (auto-created)

### Command-Line Arguments

| Argument | Short | Description | Example |
|----------|-------|-------------|---------|
| `--count` | `-c` | Number of packets to capture (0 = endless) | `-c 50` or `-c 0` |
| `--protocol` | `-p` | Filter by protocol (tcp/udp/icmp) | `-p tcp` |
| `--src-ip` | | Filter by source IP address | `--src-ip 192.168.1.1` |
| `--dest-ip` | | Filter by destination IP address | `--dest-ip 8.8.8.8` |
| `--port` | | Filter by port (source or dest) | `--port 443` |
| `--verbose` | `-v` | Show parsing errors | `-v` |
| `--export-json` | | Export captured packets to JSON | `--export-json` |
| `--export-txt` | | Export captured packets to text file | `--export-txt` |
| `--output-dir` | | Custom output directory for exports | `--output-dir logs` |
| `--help` | `-h` | Show help message | `-h` |

## 📊 Output Formats

### Terminal Display
- Color-coded by protocol (TCP=Green, UDP=Blue, ICMP=Yellow)
- Real-time packet information with headers
- Port usage analysis table (Wireshark-style)
- Reverse DNS lookups for public IPs
- Final capture statistics

### JSON Export Format
```json
{
  "metadata": {
    "capture_date": "2025-11-04T10:30:00",
    "total_packets": 100,
    "os_type": "Windows",
    "filters": {...},
    "statistics": {...}
  },
  "packets": [
    {
      "packet_number": 1,
      "timestamp": "2025-11-04T10:30:01.123456",
      "size": 60,
      "ip": {...},
      "tcp": {...},
      "hostnames": {...}
    }
  ]
}
```

### Text Export Format
- Human-readable report format
- Capture metadata and statistics
- Detailed packet-by-packet breakdown
- All headers and transport layer info
- Timestamps in ISO 8601 format

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

### ✅ Phase 1 - Foundation (Complete)
- ✅ Basic configuration and OS detection
- ✅ Raw socket creation and promiscuous mode
- ✅ Network headers parsing (Ethernet, IP, TCP, UDP, ICMP)

### ✅ Phase 2 - Advanced Features (Complete)
- ✅ Protocol filtering (TCP, UDP, ICMP)
- ✅ IP address filtering (source/destination)
- ✅ Port filtering
- ✅ Command-line arguments with argparse
- ✅ Colored output with colorama
- ✅ Port usage analysis (Wireshark-style)
- ✅ Reverse DNS lookups
- ✅ Export to JSON format
- ✅ Export to text log files
- ✅ Timestamp tracking (ISO 8601)
- ✅ Endless capture mode

### Phase 3 - Storage and Analysis (Planned)
- Advanced traffic statistics
- Top talkers analysis
- Bandwidth usage tracking
- Connection flow tracking
- Protocol distribution charts

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
├── main.py              # Main application file (~1000 lines)
├── README.md            # This file
├── requirements.txt     # Python dependencies
└── captures/            # Export directory (auto-created)
    ├── capture_YYYYMMDD_HHMMSS.json
    └── capture_YYYYMMDD_HHMMSS.txt
```

## 👨‍💻 Development

**Author:** Mathieu  
**Date:** November 2025  
**Purpose:** Cybersecurity portfolio project

## 📄 License

This is an educational project. Use responsibly and legally.

---

**Current Status:** Phase 2.3 Complete - Export Features (JSON, Text, Timestamps) ✅

**Next Phase:** Phase 3 - Advanced Storage and Analysis
