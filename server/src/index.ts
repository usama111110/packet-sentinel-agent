
import express from 'express';
import http from 'http';
import { Server as SocketServer } from 'socket.io';
import path from 'path';
import net from 'net';
import fs from 'fs';
import winston from 'winston';
import dotenv from 'dotenv';
import cors from 'cors';
import compression from 'compression';
import helmet from 'helmet';

// Load environment variables
dotenv.config();

// Configure logger
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      )
    }),
    new winston.transports.File({ filename: 'server.log' })
  ]
});

// Interface for the packet data we receive
interface Packet {
  timestamp: string;
  source: string;
  destination: string;
  protocol: string;
  length: number;
  info: string;
  data?: Uint8Array;
}

// Interface for connected agents
interface Agent {
  id: string;
  ip: string;
  hostname: string;
  connectedSince: Date;
  packetsReceived: number;
}

// Initialize Express app
const app = express();
const port = process.env.PORT || 8888;

// Apply middleware
app.use(cors());
app.use(helmet({
  contentSecurityPolicy: false // Disabled for easier development
}));
app.use(compression());
app.use(express.json());
app.use(express.static(path.join(__dirname, '../public')));

// Create HTTP server
const server = http.createServer(app);

// Initialize Socket.IO for real-time communication with web clients
const io = new SocketServer(server, {
  cors: {
    origin: '*',
    methods: ['GET', 'POST']
  }
});

// Store for captured packets (simple in-memory array)
// In production, consider using a real database
const packets: Packet[] = [];
const MAX_PACKETS = 10000; // Limit memory usage

// Store for connected agents
const agents: Map<string, Agent> = new Map();
let totalPacketsReceived = 0;

// Create a TCP server to receive packets from agents
const tcpServer = net.createServer((socket) => {
  const clientIp = socket.remoteAddress || 'unknown';
  const clientId = `${clientIp}:${socket.remotePort}`;
  
  // Register the new agent
  const agent: Agent = {
    id: clientId,
    ip: clientIp,
    hostname: `agent-${clientId}`, // Will be updated if agent sends hostname
    connectedSince: new Date(),
    packetsReceived: 0
  };
  
  agents.set(clientId, agent);
  
  logger.info(`Agent connected: ${clientId}`);
  io.emit('agent:connected', agent);
  
  // Set up data handling with buffering for messages that might be split
  let buffer = '';
  
  socket.on('data', (data) => {
    // Append data to buffer
    buffer += data.toString();
    
    // Process complete messages
    let delimiterIndex;
    while ((delimiterIndex = buffer.indexOf('\n')) !== -1) {
      const message = buffer.substring(0, delimiterIndex);
      buffer = buffer.substring(delimiterIndex + 1);
      
      try {
        const packet: Packet = JSON.parse(message);
        
        // Update agent statistics
        const agentInfo = agents.get(clientId);
        if (agentInfo) {
          agentInfo.packetsReceived++;
          agents.set(clientId, agentInfo);
        }
        
        // Store packet in our buffer
        packets.unshift(packet); // Add to front for more recent first
        if (packets.length > MAX_PACKETS) {
          packets.pop(); // Remove oldest packet if we hit the limit
        }
        
        totalPacketsReceived++;
        
        // Forward the packet to all web clients
        io.emit('packet:received', packet);
        
        // Update statistics in real-time
        if (totalPacketsReceived % 10 === 0) {
          io.emit('stats:update', {
            totalPacketsReceived,
            agents: Array.from(agents.values())
          });
        }
        
      } catch (error) {
        logger.error('Error processing packet', { error });
      }
    }
  });
  
  socket.on('close', () => {
    logger.info(`Agent disconnected: ${clientId}`);
    agents.delete(clientId);
    io.emit('agent:disconnected', { id: clientId });
  });
  
  socket.on('error', (err) => {
    logger.error(`Socket error for ${clientId}`, { error: err.message });
  });
});

// Socket.IO connection handler for web clients
io.on('connection', (socket) => {
  logger.info('Web client connected');
  
  // Send current state to the client
  socket.emit('init', {
    packets: packets.slice(0, 100), // Send only the most recent 100 packets
    agents: Array.from(agents.values()),
    stats: {
      totalPacketsReceived,
      serverStartTime: new Date().toISOString()
    }
  });
  
  // Handle client requests
  socket.on('getPackets', (options, callback) => {
    const { limit = 100, offset = 0, filter = {} } = options;
    
    // Apply filters - this is very basic, in production you'd want more sophisticated filtering
    let filteredPackets = packets;
    
    if (filter.protocol) {
      filteredPackets = filteredPackets.filter(p => p.protocol === filter.protocol);
    }
    
    if (filter.source) {
      filteredPackets = filteredPackets.filter(p => p.source.includes(filter.source));
    }
    
    if (filter.destination) {
      filteredPackets = filteredPackets.filter(p => p.destination.includes(filter.destination));
    }
    
    // Return the requested packets
    callback(filteredPackets.slice(offset, offset + limit));
  });
  
  // Handle client disconnection
  socket.on('disconnect', () => {
    logger.info('Web client disconnected');
  });
});

// Start the HTTP server for web clients
server.listen(port, () => {
  logger.info(`Web server started on port ${port}`);
  
  // Start the TCP server for agents
  tcpServer.listen(Number(port) + 1, () => {
    logger.info(`TCP server started on port ${Number(port) + 1}`);
  });
  
  logger.info('Packet Sentinel Server is running');
  logger.info(`Web dashboard available at http://localhost:${port}`);
  logger.info(`Agents should connect to TCP port ${Number(port) + 1}`);
});

// Graceful shutdown
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

function shutdown() {
  logger.info('Shutting down...');
  
  // Close TCP server
  tcpServer.close(() => {
    logger.info('TCP server closed');
    
    // Close HTTP server
    server.close(() => {
      logger.info('HTTP server closed');
      process.exit(0);
    });
  });
  
  // Force exit after 5 seconds
  setTimeout(() => {
    logger.error('Forced shutdown after timeout');
    process.exit(1);
  }, 5000);
}
