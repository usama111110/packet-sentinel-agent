
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
	installFlag   = flag.Bool("install", false, "Install as a system service")
	uninstallFlag = flag.Bool("uninstall", false, "Uninstall the system service")
	statusFlag    = flag.Bool("status", false, "Check service status")
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
}

// Program implements service.Program interface
type Program struct {
	config Config
	exit   chan struct{}
}

// Start is called when the service starts
func (p *Program) Start(s service.Service) error {
	p.exit = make(chan struct{})
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
	fmt.Println("Packet Sentinel Agent")
	fmt.Println("---------------------")
	fmt.Printf("Target server: %s\n", p.config.ServerAddr)

	// List interfaces if none specified
	if p.config.InterfaceName == "" {
		fmt.Println("Available interfaces:")
		interfaces, err := findDevices()
		if err != nil {
			log.Fatal("Failed to list interfaces: ", err)
		}
		for i, iface := range interfaces {
			fmt.Printf("[%d] %s - %s\n", i+1, iface.Name, iface.Description)
		}
		log.Fatal("Please specify an interface with --interface flag")
	}

	// Start packet capture
	fmt.Printf("Starting capture on interface: %s\n", p.config.InterfaceName)
	if p.config.BPFFilter != "" {
		fmt.Printf("Using filter: %s\n", p.config.BPFFilter)
	}

	// Connect to server
	conn, err := net.Dial("tcp", p.config.ServerAddr)
	if err != nil {
		log.Fatal("Failed to connect to server: ", err)
	}
	defer conn.Close()
	fmt.Printf("Connected to server: %s\n", p.config.ServerAddr)

	// Create a packet capture handle
	handle, err := pcap.OpenLive(p.config.InterfaceName, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal("Failed to open interface: ", err)
	}
	defer handle.Close()

	// Set filter if provided
	if p.config.BPFFilter != "" {
		if err := handle.SetBPFFilter(p.config.BPFFilter); err != nil {
			log.Fatal("Failed to set BPF filter: ", err)
		}
	}

	// Start packet processing
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetChan := packetSource.Packets()

	// Main loop
	for {
		select {
		case <-p.exit:
			fmt.Println("Agent stopping...")
			return
		case <-sigs:
			fmt.Println("Received signal, stopping...")
			return
		case packet := <-packetChan:
			if packet == nil {
				continue
			}
			
			// Process the packet
			p := processPacket(packet)
			
			// Serialize and send to server
			data, err := json.Marshal(p)
			if err != nil {
				log.Printf("Error marshaling packet: %v", err)
				continue
			}
			
			// Add newline as message delimiter
			data = append(data, '\n')
			
			_, err = conn.Write(data)
			if err != nil {
				log.Printf("Error sending packet to server: %v", err)
				
				// Try to reconnect
				conn.Close()
				conn, err = net.Dial("tcp", p.config.ServerAddr)
				if err != nil {
					log.Printf("Failed to reconnect to server: %v", err)
					time.Sleep(5 * time.Second)
				} else {
					log.Println("Reconnected to server")
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
