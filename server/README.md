
# Packet Sentinel - Server Dashboard

## Overview

This folder contains the source code for the Packet Sentinel Server, which receives packet data from multiple agents and provides a dashboard UI to monitor and analyze network traffic in real-time.

## Technical Stack

- **Frontend**: React with TypeScript
- **Styling**: Tailwind CSS
- **UI Components**: ShadCN UI
- **Visualization**: Recharts for traffic graphs and analytics
- **Server**: Node.js with Express
- **Real-time Communication**: Socket.IO

## Server Setup

### Prerequisites

1. Node.js 18 or later
2. npm or yarn package manager

### Installation

```bash
cd server
npm install
```

### Running the Server

```bash
# Development mode
npm run dev

# Production mode
npm run build
npm start
```

By default, the server listens on port 8888. This can be changed using the `PORT` environment variable:

```bash
PORT=9000 npm start
```

## Accessing the Dashboard

Once the server is running, you can access the dashboard at:

```
http://localhost:8888
```

## Server Configuration

The server can be configured using environment variables or a `.env` file:

- `PORT`: Server listening port (default: 8888)
- `TLS_CERT`: Path to TLS certificate for HTTPS (optional)
- `TLS_KEY`: Path to TLS private key for HTTPS (optional)
- `DB_PATH`: Path to store packet capture database (default: ./data)
- `LOG_LEVEL`: Logging level (default: info)

## Security Considerations

For production deployments:

1. Enable HTTPS by providing TLS certificates
2. Set up proper authentication for the dashboard
3. Configure firewall rules to restrict access to the server port
4. Consider deploying behind a reverse proxy like Nginx

## Packet Storage and Retention

By default, captured packets are stored in-memory with a retention period of 24 hours. For longer retention or persistent storage:

1. Enable the database storage option in the configuration
2. Adjust retention policies as needed
3. Consider using a dedicated database for high-volume environments
