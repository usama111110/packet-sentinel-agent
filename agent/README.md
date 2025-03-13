
# Packet Sentinel - Network Capture Agent

## Overview

Packet Sentinel Agent is a high-performance network packet capture tool written in Go. It can be compiled into a standalone executable for Windows, macOS, and Linux, with support for running as a system service that automatically starts at boot.

## Features

- **Cross-platform** - Works on Windows, macOS, and Linux
- **High-performance** packet capture using native libraries
- **Service installation** - Can run as a system service with autostart capability
- **Live capture** from network interfaces
- **PCAP file reading** for offline analysis
- **BPF filtering** for targeted packet capture
- **Reconnection logic** for reliable server communication
- **Detailed protocol detection** for common application protocols
- **Optional compression and encryption** (configurable)

## Requirements

- **Go 1.20 or later** for building
- **Platform-specific packet capture libraries:**
  - **Linux/macOS**: libpcap (`apt-get install libpcap-dev` or `brew install libpcap`)
  - **Windows**: Npcap or WinPcap (install from [npcap.com](https://npcap.com) or [winpcap.org](https://www.winpcap.org))

## Building

```bash
cd agent
go build -o packet-sentinel-agent
```

For cross-platform builds:

```bash
# Windows
GOOS=windows GOARCH=amd64 go build -o packet-sentinel-agent.exe

# macOS
GOOS=darwin GOARCH=amd64 go build -o packet-sentinel-agent-mac

# Linux
GOOS=linux GOARCH=amd64 go build -o packet-sentinel-agent-linux
```

## Usage

```bash
# Basic usage - capture and forward packets
./packet-sentinel-agent --server 192.168.1.100:8888 --interface eth0

# Apply a BPF filter (only capture TCP packets)
./packet-sentinel-agent --server 192.168.1.100:8888 --interface eth0 --filter "tcp"

# Read packets from a PCAP file
./packet-sentinel-agent --server 192.168.1.100:8888 --type file --file capture.pcap

# Enable debug output
./packet-sentinel-agent --server 192.168.1.100:8888 --interface eth0 --debug

# Enable compression and encryption
./packet-sentinel-agent --server 192.168.1.100:8888 --interface eth0 --compress --encrypt

# Limit capture to 1000 packets
./packet-sentinel-agent --server 192.168.1.100:8888 --interface eth0 --limit 1000
```

## Installing as a Service

```bash
# Install as a service (Windows, macOS, or Linux)
./packet-sentinel-agent --server 192.168.1.100:8888 --interface eth0 --install

# Check service status
./packet-sentinel-agent --status

# Uninstall service
./packet-sentinel-agent --uninstall
```

## Advanced Options

- `--snaplen` - Maximum bytes to capture per packet (default: 1600)
- `--promisc` - Set promiscuous mode (default: true)
- `--filter` - BPF filter expression (examples: "tcp", "port 80", "host 192.168.1.1")
- `--type` - Capture type: "live" or "file"
- `--file` - PCAP file to read from (when type=file)
- `--compress` - Enable compression
- `--encrypt` - Enable encryption
- `--limit` - Maximum number of packets to capture (0 = unlimited)

## Notes for Production Use

For production environments, consider the following enhancements:

1. **Implement proper encryption** (TLS or custom encryption)
2. **Add authentication** between agent and server
3. **Implement data compression** for bandwidth savings
4. **Set up proper logging** to a file or log service
5. **Configure firewalls** to allow agent-server communication
