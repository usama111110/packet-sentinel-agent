
# Packet Sentinel - Server

A simple Python-based server for receiving and displaying network packet data from Packet Sentinel agents.

## Features

- Receives packet data from multiple agents
- Displays packet information in real-time with color coding
- Logs all activity to a log file
- Tracks connected agents and their statistics
- Lightweight and easy to deploy

## Requirements

- Python 3.6 or later
- Required Python packages (install with `pip install -r requirements.txt`):
  - socket
  - colorama
  - python-dotenv

## Running the Server

1. Install the required packages:
```bash
pip install -r requirements.txt
```

2. Run the server:
```bash
python packet_sentinel_server.py
```

By default, the server listens on all interfaces (0.0.0.0) on port 8888. You can change these settings using environment variables:

```bash
SERVER_HOST=127.0.0.1 SERVER_PORT=9999 python packet_sentinel_server.py
```

## Output

The server displays captured packets in real-time with color coding:
- Blue: TCP packets
- Green: UDP packets
- Cyan: HTTP packets
- Magenta: HTTPS packets
- Yellow: DNS packets

All server activity is also logged to `packet_server.log`.

## Connecting Agents

Agents should connect to the server's IP address and port (default: 8888). Each packet should be sent as a JSON object followed by a newline character.

## Security Considerations

For production use, consider adding:
- TLS encryption for the connections
- Authentication for agents
- Access control for viewing packet data
