
import socket
import json
import threading
import time
import os
import logging
import base64
from datetime import datetime
from colorama import Fore, Style, init
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

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
        
        # Generate encryption keys
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        
        # Serialize public key for sharing with clients
        self.public_key_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

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
                        'buffer': '',
                        'symmetric_key': None  # Will be set during handshake
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

    def perform_handshake(self, client_socket, client_id):
        """Perform encryption handshake with client"""
        try:
            # First, send public key to client
            client_socket.sendall(self.public_key_pem)
            
            # Wait for encrypted symmetric key from client
            encrypted_key_data = client_socket.recv(512)  # RSA-2048 encrypted data
            
            if not encrypted_key_data:
                raise Exception("No encryption key received from client")
                
            # Decrypt symmetric key using private key
            symmetric_key = self.private_key.decrypt(
                encrypted_key_data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Store symmetric key for this client
            self.clients[client_id]['symmetric_key'] = symmetric_key
            
            print(f"{Fore.GREEN}[+] Established secure channel with {client_id}{Style.RESET_ALL}")
            logger.info(f"Established secure channel with {client_id}")
            
            # Send confirmation
            client_socket.sendall(b"SECURE_CHANNEL_ESTABLISHED")
            
            return True
            
        except Exception as e:
            print(f"{Fore.RED}[!] Handshake failed with {client_id}: {e}{Style.RESET_ALL}")
            logger.error(f"Handshake failed with {client_id}: {e}")
            return False

    def decrypt_message(self, encrypted_data, client_id):
        """Decrypt message using client's symmetric key"""
        try:
            if not self.clients[client_id]['symmetric_key']:
                raise Exception("No symmetric key available for client")
                
            # Extract IV and ciphertext
            iv = encrypted_data[:16]
            ciphertext = encrypted_data[16:]
            
            # Create decryptor
            cipher = Cipher(
                algorithms.AES(self.clients[client_id]['symmetric_key']),
                modes.CBC(iv),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            
            # Decrypt and unpad
            padded_data = decryptor.update(ciphertext) + decryptor.finalize()
            
            # PKCS7 unpadding
            padding_value = padded_data[-1]
            if padding_value > 16:
                raise ValueError("Invalid padding")
            for i in range(1, padding_value + 1):
                if padded_data[-i] != padding_value:
                    raise ValueError("Invalid padding")
                    
            plaintext = padded_data[:-padding_value]
            return plaintext.decode('utf-8', errors='ignore')
            
        except Exception as e:
            print(f"{Fore.RED}[!] Decryption error for {client_id}: {e}{Style.RESET_ALL}")
            logger.error(f"Decryption error for {client_id}: {e}")
            return None

    def handle_client(self, client_socket, client_id):
        """Handle communication with a client"""
        try:
            # First, perform encryption handshake
            if not self.perform_handshake(client_socket, client_id):
                raise Exception("Failed to establish secure channel")
                
            buffer = b""
            message_size = -1
            
            while self.running:
                # First, read message size (4 bytes)
                if message_size == -1:
                    size_data = client_socket.recv(4)
                    if not size_data or len(size_data) != 4:
                        break
                    message_size = int.from_bytes(size_data, byteorder='big')
                
                # Read the encrypted message
                data = client_socket.recv(4096)
                if not data:
                    break
                
                buffer += data
                
                # Check if we have received the complete message
                if len(buffer) >= message_size:
                    encrypted_message = buffer[:message_size]
                    buffer = buffer[message_size:]
                    message_size = -1  # Reset for next message
                    
                    # Decrypt the message
                    decrypted_message = self.decrypt_message(encrypted_message, client_id)
                    if decrypted_message:
                        self.process_packet(decrypted_message, client_id)
                
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
