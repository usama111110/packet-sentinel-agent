
# Packet Sentinel - Network Capture and Monitoring Tool

Packet Sentinel is a cross-platform network monitoring solution consisting of two main components:

1. **Packet Sentinel Agent** - A standalone executable that captures network packets on a host machine and forwards them to a central server.
2. **Packet Sentinel Server** - A central service that receives, processes, and displays network packet data from multiple agents.

## Agent Component

The agent is written in Go and uses libraries like libpcap/gopacket for packet capture. It compiles to a standalone executable that can run on:

- Windows
- macOS
- Linux

### Agent Features

- Cross-platform support
- Installation as a system service with auto-start capability
- Network interface selection
- Packet filtering support (BPF filters)
- Reliable server communication with reconnection logic
- Minimal resource usage

### Building the Agent

See the [Agent README](./agent/README.md) for detailed build instructions.

## Server Component

The server component is a Node.js application with a web-based dashboard for monitoring captured packets.

### Server Features

- Real-time packet visualization
- Multiple agent connections
- Packet filtering and search
- Protocol identification
- Detailed packet inspection
- Traffic statistics and monitoring

### Running the Server

See the [Server README](./server/README.md) for detailed setup and usage instructions.

## Deployment Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│ Agent       │     │ Agent       │     │ Agent       │
│ (Windows)   │     │ (macOS)     │     │ (Linux)     │
└──────┬──────┘     └──────┬──────┘     └──────┬──────┘
       │                   │                   │
       │   Packet Data     │   Packet Data     │   Packet Data
       │                   │                   │
       v                   v                   v
┌─────────────────────────────────────────────────────┐
│                                                     │
│              Packet Sentinel Server                 │
│                                                     │
└─────────────────────────────────────────────────────┘
                          ^
                          │
                          │   Web Interface
                          │
                          v
┌─────────────────────────────────────────────────────┐
│                                                     │
│                  Web Browser                        │
│                                                     │
└─────────────────────────────────────────────────────┘
```

## Security Considerations

This tool should be used in a controlled environment. Consider the following security aspects:

1. Agent requires administrator/root privileges to capture packets
2. Communication between agents and server is not encrypted by default
3. The server dashboard has no authentication by default

For production use, consider implementing:

1. TLS encryption for all communications
2. Authentication for the server dashboard
3. Access controls for the agent executable

## License

This project is provided as-is for educational and network troubleshooting purposes.
