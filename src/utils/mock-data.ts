
import { Packet } from '@/components/PacketTable';

// Mock network interface data
export const mockNetworkInterfaces = [
  {
    id: 'eth0',
    name: 'Ethernet',
    description: 'Intel(R) I211 Gigabit Network Connection'
  },
  {
    id: 'wlan0',
    name: 'Wi-Fi',
    description: 'Intel(R) Wi-Fi 6 AX200 160MHz'
  },
  {
    id: 'lo',
    name: 'Loopback',
    description: 'Loopback Interface'
  },
  {
    id: 'docker0',
    name: 'Docker',
    description: 'Docker Network Interface'
  }
];

// Common protocols
const protocols = ['TCP', 'UDP', 'HTTP', 'HTTPS', 'DNS', 'ICMP', 'ARP'];

// Common services and their ports
const services = [
  { name: 'HTTP', port: 80 },
  { name: 'HTTPS', port: 443 },
  { name: 'DNS', port: 53 },
  { name: 'SSH', port: 22 },
  { name: 'FTP', port: 21 },
  { name: 'SMTP', port: 25 },
  { name: 'POP3', port: 110 },
  { name: 'IMAP', port: 143 },
  { name: 'NTP', port: 123 }
];

// Mock IP addresses
const ipAddresses = [
  '192.168.1.1', '192.168.1.100', '192.168.1.101', '192.168.1.102',
  '10.0.0.1', '10.0.0.2', '10.0.0.10', '10.0.0.25',
  '172.16.0.1', '172.16.0.10', '172.16.0.100',
  '8.8.8.8', '8.8.4.4', '1.1.1.1', '9.9.9.9'
];

// Mock domain names
const domainNames = [
  'google.com', 'amazon.com', 'facebook.com', 'github.com',
  'netflix.com', 'microsoft.com', 'apple.com', 'twitter.com',
  'linkedin.com', 'youtube.com', 'instagram.com', 'reddit.com'
];

// Generate a random IP:port string
const getRandomEndpoint = () => {
  const ip = ipAddresses[Math.floor(Math.random() * ipAddresses.length)];
  const port = Math.floor(Math.random() * 60000) + 1024; // Random high port
  return `${ip}:${port}`;
};

// Generate a random service endpoint
const getRandomServiceEndpoint = () => {
  const isDomain = Math.random() > 0.5;
  const service = services[Math.floor(Math.random() * services.length)];
  
  if (isDomain) {
    const domain = domainNames[Math.floor(Math.random() * domainNames.length)];
    return `${domain}:${service.port}`;
  } else {
    const ip = ipAddresses[Math.floor(Math.random() * ipAddresses.length)];
    return `${ip}:${service.port}`;
  }
};

// Generate mock packet info based on protocol
const generatePacketInfo = (protocol: string, source: string, destination: string) => {
  switch (protocol) {
    case 'TCP':
      return `[SYN, ACK] Seq=0 Ack=1 Win=65535 Len=0`;
    case 'UDP':
      return `Source port: ${source.split(':')[1]} Destination port: ${destination.split(':')[1]} Length: ${Math.floor(Math.random() * 1000) + 100}`;
    case 'HTTP':
      return `GET /${['index.html', 'api/data', 'images/logo.png', 'css/style.css'][Math.floor(Math.random() * 4)]} HTTP/1.1`;
    case 'HTTPS':
      return `TLSv1.2 Application Data Protocol: https`;
    case 'DNS':
      return `Standard query ${Math.random() > 0.5 ? '0x1a2b' : '0xc4d3'} A ${domainNames[Math.floor(Math.random() * domainNames.length)]}`;
    case 'ICMP':
      return `Echo (ping) request id=${Math.floor(Math.random() * 65535)}, seq=${Math.floor(Math.random() * 100)}, ttl=${Math.floor(Math.random() * 64) + 1}`;
    case 'ARP':
      return `Who has ${ipAddresses[Math.floor(Math.random() * ipAddresses.length)]}? Tell ${ipAddresses[Math.floor(Math.random() * ipAddresses.length)]}`;
    default:
      return `Unknown protocol data`;
  }
};

// Generate a random packet of mock data
const generateRandomPacket = (id: string): Packet => {
  const protocol = protocols[Math.floor(Math.random() * protocols.length)];
  
  // Adjust endpoints based on protocol
  let source, destination;
  
  if (['HTTP', 'HTTPS'].includes(protocol)) {
    // For HTTP/HTTPS, typically client -> server
    source = getRandomEndpoint();
    destination = getRandomServiceEndpoint();
  } else if (protocol === 'DNS') {
    // For DNS, typically client -> DNS server
    source = getRandomEndpoint();
    destination = `${['8.8.8.8', '1.1.1.1', '9.9.9.9'][Math.floor(Math.random() * 3)]}:53`;
  } else {
    // For other protocols
    source = getRandomEndpoint();
    destination = getRandomEndpoint();
  }
  
  return {
    id,
    timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19),
    protocol,
    source,
    destination,
    size: Math.floor(Math.random() * 1460) + 40, // Random size between 40 and 1500 bytes (typical Ethernet)
    info: generatePacketInfo(protocol, source, destination)
  };
};

// Generate a specified number of mock packets
export const generateMockPackets = (count: number): Packet[] => {
  return Array.from({ length: count }, (_, i) => 
    generateRandomPacket(`pkt-${Date.now()}-${i}`)
  );
};
