
# Packet Sentinel - Server

A simple Python-based server for receiving and displaying network packet data from Packet Sentinel agents.

## Features

- Receives packet data from multiple agents
- Displays packet information in real-time with color coding
- Logs all activity to a log file
- Tracks connected agents and their statistics
- Lightweight and easy to deploy
- Secure encrypted communication using AES-256 and RSA key exchange

## Requirements

- Python 3.6 or later
- Required Python packages (install with `pip install -r requirements.txt`):
  - socket
  - colorama
  - python-dotenv
  - cryptography

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

## Security

The server implements a secure communication channel with agents:

1. RSA-2048 key exchange for initial handshake
2. AES-256-CBC for symmetric encryption of packet data
3. Message integrity verification

This ensures that packet data transmitted from agents cannot be intercepted or read by unauthorized parties.

## Output

The server displays captured packets in real-time with color coding:
- Blue: TCP packets
- Green: UDP packets
- Cyan: HTTP packets
- Magenta: HTTPS packets
- Yellow: DNS packets

All server activity is also logged to `packet_server.log`.

## Connecting Agents

Agents automatically establish a secure connection with the server:
1. The agent connects to the server and receives the server's public key
2. The agent generates a random AES-256 key and encrypts it with the server's public key
3. The agent sends the encrypted AES key to the server
4. All subsequent communication is encrypted using the AES key

Each packet is encrypted, sent with a size header, and decrypted by the server.

## Performance Considerations

The server is designed to handle high-volume packet capture:
- Multithreaded design for parallel processing of agent connections
- Efficient packet handling and storage
- Optimized encryption/decryption operations

For extremely high-volume environments, consider:
- Running on a dedicated high-performance server
- Increasing available memory for packet storage
- Distributing the load across multiple server instances
