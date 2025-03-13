
# Packet Sentinel - Network Capture Agent

## Overview

This folder contains the source code for the Packet Sentinel Agent, a cross-platform network packet capture tool that can be compiled into a standalone executable for Windows, macOS, and Linux.

## Technical Stack

- **Language**: Go (Golang)
- **Network Capture**: libpcap/gopacket
- **Packaging**: goreleaser for cross-platform executables
- **Service Management**: Native support for systemd (Linux), launchd (macOS), and Windows Services

## Building the Agent

### Prerequisites

1. Install Go 1.20 or later
2. Install libpcap development libraries:
   - Ubuntu/Debian: `sudo apt-get install libpcap-dev`
   - macOS: `brew install libpcap`
   - Windows: Install WinPcap or Npcap development kit

### Build Commands

```bash
# Build for the current platform
cd agent
go build -o bin/packet-sentinel-agent

# Cross-compile for all platforms (requires goreleaser)
goreleaser build --snapshot --clean
```

## Running the Agent

The agent can be run directly from the command line:

```bash
./packet-sentinel-agent --server 192.168.1.100:8888
```

### Command Line Options

- `--server`: Server address and port (required)
- `--interface`: Network interface to capture (optional, will list available interfaces if not specified)
- `--filter`: BPF filter expression (optional)
- `--install`: Install as a system service
- `--uninstall`: Uninstall the system service
- `--status`: Check the status of the system service

## Installing as a Service

### Linux (systemd)

```bash
sudo ./packet-sentinel-agent --install --server 192.168.1.100:8888
```

### macOS (launchd)

```bash
./packet-sentinel-agent --install --server 192.168.1.100:8888
```

### Windows

```bash
packet-sentinel-agent.exe --install --server 192.168.1.100:8888
```

## Service Management

### Linux

```bash
# Start the service
sudo systemctl start packet-sentinel-agent

# Stop the service
sudo systemctl stop packet-sentinel-agent

# Enable autostart
sudo systemctl enable packet-sentinel-agent
```

### macOS

```bash
# Start the service
launchctl load ~/Library/LaunchAgents/dev.lovable.packet-sentinel-agent.plist

# Stop the service
launchctl unload ~/Library/LaunchAgents/dev.lovable.packet-sentinel-agent.plist
```

### Windows

```bash
# Start the service
sc start PacketSentinelAgent

# Stop the service
sc stop PacketSentinelAgent
```

## Security Considerations

Running the agent requires administrative/root privileges to capture network packets. Make sure to:

1. Restrict access to the agent executable
2. Use TLS for communication with the server
3. Implement proper authentication if deployed in production
