
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
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
	encryption    = flag.Bool("encrypt", false, "Enable encryption")
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
			
			// Apply encryption if enabled
			if p.config.Encryption {
				// Simple encryption placeholder - in production, use a proper encryption library
				// This is where you would encrypt the data with AES, etc.
			}
			
			// Add newline as message delimiter
			data = append(data, '\n')
			
			_, err = conn.Write(data)
			if err != nil {
				logMessage(p.logger, fmt.Sprintf("Error sending packet to server: %v", err))
				
				// Try to reconnect
				conn.Close()
				conn, err = net.Dial("tcp", p.config.ServerAddr)
				if err != nil {
					logMessage(p.logger, fmt.Sprintf("Failed to reconnect to server: %v", err))
					time.Sleep(5 * time.Second)
				} else {
					logMessage(p.logger, "Reconnected to server")
				}
			}
		}
	}
}

// processPacket converts a gopacket.Packet to our Packet struct
func processPacket(packet gopacket.Packet) Packet {
	p := Packet{
		Timestamp: packet.Metadata().Timestamp,
		Length:    packet.Metadata().Length,
		Hostname:  "unknown",  // Will be set in run()
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
		data := appLayer.Payload()
		if len(data) > 100 {
			data = data[:100] // Truncate long payloads
		}
		p.Data = data
		
		// Try to determine the application protocol
		if bytes.Contains(data, []byte("HTTP")) {
			p.Protocol = "HTTP"
			// Extract first line of HTTP request/response
			if i := bytes.IndexByte(data, '\n'); i > 0 {
				p.Info = string(data[:i])
			}
		} else if bytes.Contains(data, []byte("SSH")) {
			p.Protocol = "SSH"
		} else if len(data) > 2 && data[0] == 0x16 && data[1] == 0x03 {
			p.Protocol = "TLS"
		} else if bytes.Contains(data, []byte("DNS")) {
			p.Protocol = "DNS"
		} else if bytes.Contains(data, []byte("SMTP")) {
			p.Protocol = "SMTP"
		} else if bytes.Contains(data, []byte("FTP")) {
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
