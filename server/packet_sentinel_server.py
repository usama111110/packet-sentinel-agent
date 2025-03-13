
import socket
import json
import threading
import time
import os
import logging
from datetime import datetime
from colorama import Fore, Style, init

# Initialize colorama
init()

# Set up logging
logging.basicConfig(
    filename='packet_server.log',
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('PacketSentinel')

class PacketServer:
    def __init__(self, host='0.0.0.0', port=8888):
        self.host = host
        self.port = port
        self.server_socket = None
        self.clients = {}  # Store client connections
        self.packets = []  # Store received packets
        self.running = False
        self.max_packets = 10000  # Maximum packets to keep in memory

    def start(self):
        """Start the packet server"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.running = True
            
            print(f"{Fore.GREEN}[+] Server started on {self.host}:{self.port}{Style.RESET_ALL}")
            logger.info(f"Server started on {self.host}:{self.port}")
            
            # Start stats reporting thread
            stats_thread = threading.Thread(target=self.report_stats)
            stats_thread.daemon = True
            stats_thread.start()
            
            # Accept incoming connections
            while self.running:
                try:
                    client_socket, address = self.server_socket.accept()
                    client_id = f"{address[0]}:{address[1]}"
                    print(f"{Fore.CYAN}[*] New connection from {client_id}{Style.RESET_ALL}")
                    logger.info(f"New agent connection from {client_id}")
                    
                    # Store client information
                    self.clients[client_id] = {
                        'socket': client_socket,
                        'address': address,
                        'connected_time': time.time(),
                        'packets_received': 0,
                        'hostname': 'unknown',
                        'buffer': ''
                    }
                    
                    # Start a thread to handle this client
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, client_id)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                    
                except Exception as e:
                    if self.running:
                        print(f"{Fore.RED}[!] Error accepting connection: {e}{Style.RESET_ALL}")
                        logger.error(f"Error accepting connection: {e}")
                    
        except Exception as e:
            print(f"{Fore.RED}[!] Server error: {e}{Style.RESET_ALL}")
            logger.error(f"Server error: {e}")
            
        finally:
            self.shutdown()

    def handle_client(self, client_socket, client_id):
        """Handle communication with a client"""
        try:
            buffer = ""
            while self.running:
                data = client_socket.recv(4096)
                if not data:
                    break
                
                # Add data to buffer and process complete messages
                buffer += data.decode('utf-8', errors='ignore')
                
                # Process complete messages that end with newline
                while '\n' in buffer:
                    message, buffer = buffer.split('\n', 1)
                    self.process_packet(message, client_id)
                
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Error handling client {client_id}: {e}{Style.RESET_ALL}")
            logger.error(f"Error handling client {client_id}: {e}")
            
        finally:
            # Close and remove client
            try:
                client_socket.close()
            except:
                pass
                
            if client_id in self.clients:
                print(f"{Fore.YELLOW}[-] Client disconnected: {client_id}{Style.RESET_ALL}")
                logger.info(f"Agent disconnected: {client_id}")
                del self.clients[client_id]

    def process_packet(self, packet_data, client_id):
        """Process a received packet"""
        try:
            packet = json.loads(packet_data)
            
            # Add client information to the packet
            packet['client_id'] = client_id
            packet['received_time'] = datetime.now().isoformat()
            
            # Update client stats
            if client_id in self.clients:
                self.clients[client_id]['packets_received'] += 1
                
                # Update hostname if packet includes it
                if 'hostname' in packet and packet['hostname'] != 'unknown':
                    self.clients[client_id]['hostname'] = packet['hostname']
            
            # Add to packets list (limit size)
            self.packets.insert(0, packet)  # Add to front (newest first)
            if len(self.packets) > self.max_packets:
                self.packets.pop()  # Remove oldest
            
            # Log successful packet receipt
            logger.info(f"Packet received from {client_id} - {packet['protocol']} {packet['source']} -> {packet['destination']}")
            
            # Display packet information
            protocol = packet.get('protocol', 'Unknown')
            src = packet.get('source', 'Unknown')
            dst = packet.get('destination', 'Unknown')
            length = packet.get('length', 0)
            info = packet.get('info', '')
            
            protocol_color = Fore.WHITE
            if protocol.lower() == 'tcp':
                protocol_color = Fore.BLUE
            elif protocol.lower() == 'udp':
                protocol_color = Fore.GREEN
            elif protocol.lower() == 'http':
                protocol_color = Fore.CYAN
            elif protocol.lower() == 'https':
                protocol_color = Fore.MAGENTA
            elif protocol.lower() == 'dns':
                protocol_color = Fore.YELLOW
            
            # Print packet details
            hostname = self.clients[client_id]['hostname'] if client_id in self.clients else 'unknown'
            print(f"[{Fore.CYAN}{hostname}{Style.RESET_ALL}] {protocol_color}{protocol}{Style.RESET_ALL} " +
                  f"{Fore.WHITE}{src}{Style.RESET_ALL} -> {Fore.WHITE}{dst}{Style.RESET_ALL} " +
                  f"({length} bytes) {Fore.YELLOW}{info[:100]}{Style.RESET_ALL}")
            
        except json.JSONDecodeError:
            print(f"{Fore.RED}[!] Invalid JSON data from {client_id}{Style.RESET_ALL}")
            logger.error(f"Invalid JSON data from {client_id}")
        except Exception as e:
            print(f"{Fore.RED}[!] Error processing packet: {e}{Style.RESET_ALL}")
            logger.error(f"Error processing packet: {e}")

    def report_stats(self):
        """Periodically report server statistics"""
        while self.running:
            time.sleep(10)
            client_count = len(self.clients)
            packet_count = sum(c['packets_received'] for c in self.clients.values())
            
            print(f"{Fore.GREEN}[*] Server Stats: {client_count} connected agents, {packet_count} total packets received{Style.RESET_ALL}")
            logger.info(f"Server Stats: {client_count} connected agents, {packet_count} total packets received")
            
            # Log details for each connected client
            for client_id, client_data in self.clients.items():
                hostname = client_data['hostname']
                connected_time = time.strftime('%H:%M:%S', time.localtime(client_data['connected_time']))
                packets = client_data['packets_received']
                
                print(f"  - {Fore.CYAN}{hostname}{Style.RESET_ALL} ({client_id}) connected since {connected_time}, {packets} packets")

    def shutdown(self):
        """Shut down the server"""
        self.running = False
        
        # Close all client connections
        for client_id, client_data in list(self.clients.items()):
            try:
                client_data['socket'].close()
            except:
                pass
                
        # Close server socket
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
                
        print(f"{Fore.YELLOW}[-] Server shut down{Style.RESET_ALL}")
        logger.info("Server shut down")

if __name__ == "__main__":
    try:
        # Get server configuration from environment or use defaults
        host = os.environ.get('SERVER_HOST', '0.0.0.0')
        port = int(os.environ.get('SERVER_PORT', 8888))
        
        server = PacketServer(host, port)
        server.start()
    except KeyboardInterrupt:
        print(f"{Fore.YELLOW}[-] Server stopped by user{Style.RESET_ALL}")
        logger.info("Server stopped by user")
    except Exception as e:
        print(f"{Fore.RED}[!] Unhandled exception: {e}{Style.RESET_ALL}")
        logger.error(f"Unhandled exception: {e}")
