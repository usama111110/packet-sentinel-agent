
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/kardianos/service"
)

var (
	serverAddr    = flag.String("server", "", "Server address (required, format: host:port)")
	interfaceName = flag.String("interface", "", "Interface to capture packets from")
	bpfFilter     = flag.String("filter", "", "BPF filter expression")
	captureLimit  = flag.Int("limit", 0, "Maximum number of packets to capture (0 = unlimited)")
	snapLen       = flag.Int("snaplen", 1600, "Maximum bytes to capture per packet")
	promisc       = flag.Bool("promisc", true, "Set promiscuous mode")
	captureType   = flag.String("type", "live", "Capture type: live or file")
	pcapFile      = flag.String("file", "", "PCAP file to read from (when type=file)")
	compression   = flag.Bool("compress", false, "Enable compression")
	encryption    = flag.Bool("encrypt", true, "Enable encryption (default: true)")
	installFlag   = flag.Bool("install", false, "Install as a system service")
	uninstallFlag = flag.Bool("uninstall", false, "Uninstall the system service")
	statusFlag    = flag.Bool("status", false, "Check service status")
	debugFlag     = flag.Bool("debug", false, "Enable debug logging")
)

// Packet represents a captured network packet
type Packet struct {
	Timestamp   time.Time `json:"timestamp"`
	Source      string    `json:"source"`
	Destination string    `json:"destination"`
	Protocol    string    `json:"protocol"`
	Length      int       `json:"length"`
	Info        string    `json:"info"`
	Data        []byte    `json:"data,omitempty"`
	Hostname    string    `json:"hostname"`
}

// Interface represents a network interface
type Interface struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

// Config holds the program configuration
type Config struct {
	ServerAddr    string
	InterfaceName string
	BPFFilter     string
	CaptureLimit  int
	SnapLen       int
	Promisc       bool
	CaptureType   string
	PCAPFile      string
	Compression   bool
	Encryption    bool
	Debug         bool
}

// Program implements service.Program interface
type Program struct {
	config Config
	exit   chan struct{}
	logger service.Logger
}

// CryptoContext holds encryption-related data
type CryptoContext struct {
	ServerPublicKey *rsa.PublicKey
	SymmetricKey    []byte
	Ready           bool
}

// Start is called when the service starts
func (p *Program) Start(s service.Service) error {
	p.exit = make(chan struct{})
	p.logger = s.Logger
	go p.run()
	return nil
}

// Stop is called when the service stops
func (p *Program) Stop(s service.Service) error {
	close(p.exit)
	return nil
}

func main() {
	// Parse command-line arguments
	flag.Parse()

	// Create service configuration
	svcConfig := &service.Config{
		Name:        "PacketSentinelAgent",
		DisplayName: "Packet Sentinel Agent",
		Description: "Network packet capture and forwarding agent",
	}

	// Create program with configuration
	config := Config{
		ServerAddr:    *serverAddr,
		InterfaceName: *interfaceName,
		BPFFilter:     *bpfFilter,
		CaptureLimit:  *captureLimit,
		SnapLen:       *snapLen,
		Promisc:       *promisc,
		CaptureType:   *captureType,
		PCAPFile:      *pcapFile,
		Compression:   *compression,
		Encryption:    *encryption,
		Debug:         *debugFlag,
	}

	prg := &Program{config: config}
	s, err := service.New(prg, svcConfig)
	if err != nil {
		log.Fatal(err)
	}

	// Handle service installation/uninstallation
	if *installFlag {
		if *serverAddr == "" {
			log.Fatal("Server address is required for installation. Use --server flag.")
		}
		err = s.Install()
		if err != nil {
			log.Fatal("Failed to install service: ", err)
		}
		fmt.Println("Service installed successfully")
		return
	}

	if *uninstallFlag {
		err = s.Uninstall()
		if err != nil {
			log.Fatal("Failed to uninstall service: ", err)
		}
		fmt.Println("Service uninstalled successfully")
		return
	}

	if *statusFlag {
		status, err := s.Status()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("Service status:", serviceStatusString(status))
		return
	}

	// If no service commands, run as application
	if *serverAddr == "" {
		flag.Usage()
		log.Fatal("Server address is required. Use --server flag.")
	}

	// Run interactively if not running as a service
	err = s.Run()
	if err != nil {
		log.Fatal(err)
	}
}

func (p *Program) run() {
	// Setup signal handler for graceful shutdown
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	// Print application info
	logMessage(p.logger, "Packet Sentinel Agent starting")
	logMessage(p.logger, fmt.Sprintf("Target server: %s", p.config.ServerAddr))

	// Get hostname for packet identification
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown-host"
		logMessage(p.logger, fmt.Sprintf("Warning: Could not determine hostname: %v", err))
	}

	// List interfaces if none specified
	if p.config.InterfaceName == "" && p.config.CaptureType != "file" {
		logMessage(p.logger, "Available interfaces:")
		interfaces, err := findDevices()
		if err != nil {
			logMessage(p.logger, fmt.Sprintf("Failed to list interfaces: %v", err))
			return
		}
		for i, iface := range interfaces {
			logMessage(p.logger, fmt.Sprintf("[%d] %s - %s", i+1, iface.Name, iface.Description))
		}
		logMessage(p.logger, "Please specify an interface with --interface flag")
		return
	}

	// Validate capture type
	if p.config.CaptureType == "file" && p.config.PCAPFile == "" {
		logMessage(p.logger, "PCAP file path is required when using --type=file")
		return
	}

	// Start packet capture
	if p.config.CaptureType == "file" {
		logMessage(p.logger, fmt.Sprintf("Reading from PCAP file: %s", p.config.PCAPFile))
	} else {
		logMessage(p.logger, fmt.Sprintf("Starting capture on interface: %s", p.config.InterfaceName))
	}
	
	if p.config.BPFFilter != "" {
		logMessage(p.logger, fmt.Sprintf("Using filter: %s", p.config.BPFFilter))
	}

	// Connect to server
	conn, err := net.Dial("tcp", p.config.ServerAddr)
	if err != nil {
		logMessage(p.logger, fmt.Sprintf("Failed to connect to server: %v", err))
		return
	}
	defer conn.Close()
	logMessage(p.logger, fmt.Sprintf("Connected to server: %s", p.config.ServerAddr))

	// Set up encryption if enabled
	var cryptoCtx CryptoContext
	if p.config.Encryption {
		cryptoCtx, err = performHandshake(conn)
		if err != nil {
			logMessage(p.logger, fmt.Sprintf("Failed to establish secure channel: %v", err))
			return
		}
		logMessage(p.logger, "Secure channel established with server")
	}

	// Create a packet source
	var packetSource *gopacket.PacketSource
	var handle *pcap.Handle

	if p.config.CaptureType == "file" {
		// Open PCAP file
		handle, err = pcap.OpenOffline(p.config.PCAPFile)
		if err != nil {
			logMessage(p.logger, fmt.Sprintf("Failed to open PCAP file: %v", err))
			return
		}
	} else {
		// Open live capture
		handle, err = pcap.OpenLive(
			p.config.InterfaceName,
			int32(p.config.SnapLen),
			p.config.Promisc,
			pcap.BlockForever,
		)
		if err != nil {
			logMessage(p.logger, fmt.Sprintf("Failed to open interface: %v", err))
			return
		}
	}
	defer handle.Close()

	// Set filter if provided
	if p.config.BPFFilter != "" {
		if err := handle.SetBPFFilter(p.config.BPFFilter); err != nil {
			logMessage(p.logger, fmt.Sprintf("Failed to set BPF filter: %v", err))
			return
		}
	}

	// Create packet source
	packetSource = gopacket.NewPacketSource(handle, handle.LinkType())
	packetChan := packetSource.Packets()

	// Track packet statistics
	packetsProcessed := 0
	startTime := time.Now()
	lastReportTime := startTime
	
	// Start a goroutine to report statistics
	if p.config.Debug {
		go func() {
			ticker := time.NewTicker(10 * time.Second)
			defer ticker.Stop()
			
			for {
				select {
				case <-p.exit:
					return
				case <-ticker.C:
					duration := time.Since(startTime)
					rate := float64(packetsProcessed) / duration.Seconds()
					logMessage(p.logger, fmt.Sprintf("Stats: Captured %d packets (%.2f packets/sec)", 
						packetsProcessed, rate))
				}
			}
		}()
	}

	// Main loop
	for {
		select {
		case <-p.exit:
			logMessage(p.logger, "Agent stopping...")
			return
		case <-sigs:
			logMessage(p.logger, "Received signal, stopping...")
			return
		case packet, ok := <-packetChan:
			if !ok {
				if p.config.CaptureType == "file" {
					logMessage(p.logger, "Finished reading PCAP file")
					return
				}
				continue
			}
			
			// Process the packet
			p := processPacket(packet)
			
			// Add hostname
			p.Hostname = hostname
			
			// Update packet counter
			packetsProcessed++
			
			// Check if we've reached the limit
			if p.config.CaptureLimit > 0 && packetsProcessed >= p.config.CaptureLimit {
				logMessage(p.logger, fmt.Sprintf("Reached packet limit of %d, stopping", p.config.CaptureLimit))
				return
			}
			
			// Serialize and send to server
			data, err := json.Marshal(p)
			if err != nil {
				logMessage(p.logger, fmt.Sprintf("Error marshaling packet: %v", err))
				continue
			}
			
			// Apply compression if enabled
			if p.config.Compression {
				// Simple compression placeholder - in production, use a proper compression library
				// This is where you would compress the data with zlib, gzip, etc.
			}
			
			// Apply encryption if enabled and send
			var sendErr error
			if p.config.Encryption && cryptoCtx.Ready {
				sendErr = sendEncrypted(conn, data, cryptoCtx)
			} else {
				// If encryption is disabled or not ready, send with newline delimiter (legacy mode)
				data = append(data, '\n')
				_, sendErr = conn.Write(data)
			}
			
			if sendErr != nil {
				logMessage(p.logger, fmt.Sprintf("Error sending packet to server: %v", sendErr))
				
				// Try to reconnect
				conn.Close()
				conn, err = net.Dial("tcp", p.config.ServerAddr)
				if err != nil {
					logMessage(p.logger, fmt.Sprintf("Failed to reconnect to server: %v", err))
					time.Sleep(5 * time.Second)
				} else {
					logMessage(p.logger, "Reconnected to server")
					
					// Re-establish encryption if needed
					if p.config.Encryption {
						cryptoCtx, err = performHandshake(conn)
						if err != nil {
							logMessage(p.logger, fmt.Sprintf("Failed to re-establish secure channel: %v", err))
							return
						}
						logMessage(p.logger, "Secure channel re-established with server")
					}
				}
			}
		}
	}
}

// performHandshake establishes a secure channel with the server
func performHandshake(conn net.Conn) (CryptoContext, error) {
	var ctx CryptoContext
	
	// Read server's public key
	pemData := make([]byte, 4096)
	n, err := conn.Read(pemData)
	if err != nil {
		return ctx, fmt.Errorf("failed to read server public key: %v", err)
	}
	
	// Parse the public key
	block, _ := pem.Decode(pemData[:n])
	if block == nil || block.Type != "PUBLIC KEY" {
		return ctx, fmt.Errorf("failed to decode PEM block containing public key")
	}
	
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return ctx, fmt.Errorf("failed to parse public key: %v", err)
	}
	
	var ok bool
	ctx.ServerPublicKey, ok = pubInterface.(*rsa.PublicKey)
	if !ok {
		return ctx, fmt.Errorf("not an RSA public key")
	}
	
	// Generate a random symmetric key (AES-256)
	ctx.SymmetricKey = make([]byte, 32) // 256 bits
	if _, err := io.ReadFull(rand.Reader, ctx.SymmetricKey); err != nil {
		return ctx, fmt.Errorf("failed to generate symmetric key: %v", err)
	}
	
	// Encrypt the symmetric key with the server's public key
	encryptedKey, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		ctx.ServerPublicKey,
		ctx.SymmetricKey,
		nil,
	)
	if err != nil {
		return ctx, fmt.Errorf("failed to encrypt symmetric key: %v", err)
	}
	
	// Send the encrypted key to the server
	_, err = conn.Write(encryptedKey)
	if err != nil {
		return ctx, fmt.Errorf("failed to send encrypted key: %v", err)
	}
	
	// Wait for confirmation
	confirmation := make([]byte, 26) // "SECURE_CHANNEL_ESTABLISHED"
	n, err = conn.Read(confirmation)
	if err != nil || string(confirmation[:n]) != "SECURE_CHANNEL_ESTABLISHED" {
		return ctx, fmt.Errorf("failed to receive confirmation: %v", err)
	}
	
	ctx.Ready = true
	return ctx, nil
}

// sendEncrypted encrypts and sends a message using the established secure channel
func sendEncrypted(conn net.Conn, data []byte, ctx CryptoContext) error {
	// Create padded data (PKCS#7 padding)
	blockSize := aes.BlockSize
	padding := blockSize - (len(data) % blockSize)
	paddedData := make([]byte, len(data)+padding)
	copy(paddedData, data)
	for i := len(data); i < len(paddedData); i++ {
		paddedData[i] = byte(padding)
	}
	
	// Generate random IV
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return fmt.Errorf("failed to generate IV: %v", err)
	}
	
	// Create AES cipher
	block, err := aes.NewCipher(ctx.SymmetricKey)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %v", err)
	}
	
	// Create encryptor
	mode := cipher.NewCBCEncrypter(block, iv)
	ciphertext := make([]byte, len(paddedData))
	mode.CryptBlocks(ciphertext, paddedData)
	
	// Prepend IV to the ciphertext
	encrypted := append(iv, ciphertext...)
	
	// Calculate and send message size
	messageSize := len(encrypted)
	sizeBuf := make([]byte, 4)
	sizeBuf[0] = byte(messageSize >> 24)
	sizeBuf[1] = byte(messageSize >> 16)
	sizeBuf[2] = byte(messageSize >> 8)
	sizeBuf[3] = byte(messageSize)
	
	_, err = conn.Write(sizeBuf)
	if err != nil {
		return fmt.Errorf("failed to send message size: %v", err)
	}
	
	// Send encrypted data
	_, err = conn.Write(encrypted)
	if err != nil {
		return fmt.Errorf("failed to send encrypted data: %v", err)
	}
	
	return nil
}

// processPacket converts a gopacket.Packet to our Packet struct
func processPacket(packet gopacket.Packet) Packet {
	p := Packet{
		Timestamp: packet.Metadata().Timestamp,
		Length:    packet.Metadata().Length,
		Hostname:  "unknown",  // Will be set in run()
		Data:      packet.Data(), // Include full packet data
	}

	// Extract network layer info
	if netLayer := packet.NetworkLayer(); netLayer != nil {
		p.Source = netLayer.NetworkFlow().Src().String()
		p.Destination = netLayer.NetworkFlow().Dst().String()
	}

	// Extract transport layer info
	if transportLayer := packet.TransportLayer(); transportLayer != nil {
		p.Protocol = transportLayer.LayerType().String()
		
		// If TCP or UDP, append port information
		p.Source += ":" + transportLayer.TransportFlow().Src().String()
		p.Destination += ":" + transportLayer.TransportFlow().Dst().String()
	} else if networkLayer := packet.NetworkLayer(); networkLayer != nil {
		p.Protocol = networkLayer.LayerType().String()
	} else {
		p.Protocol = "Unknown"
	}

	// Extract application layer info
	if appLayer := packet.ApplicationLayer(); appLayer != nil {
		appData := appLayer.Payload()
		
		// Try to determine the application protocol
		if bytes.Contains(appData, []byte("HTTP")) {
			p.Protocol = "HTTP"
			// Extract first line of HTTP request/response
			if i := bytes.IndexByte(appData, '\n'); i > 0 {
				p.Info = string(appData[:i])
			}
		} else if bytes.Contains(appData, []byte("SSH")) {
			p.Protocol = "SSH"
		} else if len(appData) > 2 && appData[0] == 0x16 && appData[1] == 0x03 {
			p.Protocol = "TLS"
		} else if bytes.Contains(appData, []byte("DNS")) {
			p.Protocol = "DNS"
		} else if bytes.Contains(appData, []byte("SMTP")) {
			p.Protocol = "SMTP"
		} else if bytes.Contains(appData, []byte("FTP")) {
			p.Protocol = "FTP"
		}
	}
	
	// If Info is still empty, provide basic packet info
	if p.Info == "" {
		p.Info = fmt.Sprintf("%s -> %s (%d bytes)", p.Source, p.Destination, p.Length)
	}

	return p
}

// findDevices returns a list of available network interfaces
func findDevices() ([]Interface, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return nil, err
	}

	var interfaces []Interface
	for i, device := range devices {
		// Skip loopback interfaces unless there are no other options
		isLoopback := false
		for _, addr := range device.Addresses {
			ip := addr.IP
			if ip.IsLoopback() {
				isLoopback = true
				break
			}
		}
		
		if isLoopback && i < len(devices)-1 {
			continue
		}
		
		// Create interface description
		desc := device.Description
		if desc == "" {
			desc = "No description available"
		}
		
		iface := Interface{
			ID:          device.Name,
			Name:        device.Name,
			Description: desc,
		}
		interfaces = append(interfaces, iface)
	}

	return interfaces, nil
}

// serviceStatusString converts service.Status to a string
func serviceStatusString(status service.Status) string {
	switch status {
	case service.StatusRunning:
		return "Running"
	case service.StatusStopped:
		return "Stopped"
	default:
		return "Unknown"
	}
}

// logMessage logs a message to the service logger and stdout
func logMessage(logger service.Logger, message string) {
	if logger != nil {
		logger.Info(message)
	}
	fmt.Println(message)
}
