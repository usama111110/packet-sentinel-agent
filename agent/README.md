
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
- **Full packet capture** - Captures and forwards complete packet data
- **End-to-end encryption** - Secure channel using RSA key exchange and AES-256 encryption

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

# Disable encryption (not recommended)
./packet-sentinel-agent --server 192.168.1.100:8888 --interface eth0 --encrypt=false

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

## Security Features

The agent implements strong security measures:

1. **Encryption Handshake**:
   - Receives the server's RSA-2048 public key
   - Generates a random AES-256 symmetric key
   - Encrypts the symmetric key using the server's public key
   - Establishes a secure channel for all subsequent communication

2. **Packet Encryption**:
   - All packet data is encrypted using AES-256 in CBC mode
   - A unique IV is generated for each packet
   - PKCS#7 padding ensures proper block alignment
   - Message size is sent as a header for efficient transmission

3. **Connection Resilience**:
   - Automatically reconnects if the server connection is lost
   - Re-establishes the secure channel after reconnection
   - Maintains encryption parameters across reconnects

## Advanced Options

- `--snaplen` - Maximum bytes to capture per packet (default: 1600)
- `--promisc` - Set promiscuous mode (default: true)
- `--filter` - BPF filter expression (examples: "tcp", "port 80", "host 192.168.1.1")
- `--type` - Capture type: "live" or "file"
- `--file` - PCAP file to read from (when type=file)
- `--compress` - Enable compression
- `--encrypt` - Enable encryption (default: true)
- `--limit` - Maximum number of packets to capture (0 = unlimited)

## Performance Considerations

For high-volume network environments:

1. **Increase buffer sizes** using `--snaplen` parameter
2. **Use specific BPF filters** to reduce capture volume
3. **Run on a dedicated machine** with sufficient CPU and memory
4. **Use a high-performance network card** with hardware acceleration
5. **Monitor disk space** when capturing full packet data
