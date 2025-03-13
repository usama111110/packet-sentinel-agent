
import React, { useState, useEffect } from 'react';
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Play, Pause, Database, DownloadCloud } from "lucide-react";
import { useToast } from "@/components/ui/use-toast";
import { generateMockPackets } from "@/utils/mock-data";
import { Packet } from "@/components/PacketTable";
import PacketTable from "@/components/PacketTable";
import PacketDetails from "@/components/PacketDetails";
import ServerStatusCard from "@/components/ServerStatusCard";

export const ServerPage: React.FC = () => {
  const { toast } = useToast();
  const [serverPort, setServerPort] = useState('8888');
  const [isServerRunning, setIsServerRunning] = useState(false);
  const [serverUptime, setServerUptime] = useState('00:00:00');
  const [serverStartTime, setServerStartTime] = useState<Date | null>(null);
  const [packets, setPackets] = useState<Packet[]>([]);
  const [selectedPacket, setSelectedPacket] = useState<Packet | null>(null);
  const [connectedClients, setConnectedClients] = useState<any[]>([]);
  const [totalPacketsReceived, setTotalPacketsReceived] = useState(0);
  
  // Mock starting/stopping server
  const handleServerToggle = () => {
    setIsServerRunning(!isServerRunning);
    
    if (!isServerRunning) {
      // Start the server
      setServerStartTime(new Date());
      setPackets([]);
      setSelectedPacket(null);
      setTotalPacketsReceived(0);
      
      toast({
        title: "Server started",
        description: `Listening for agent connections on port ${serverPort}`,
      });
      
      // Simulate client connections after a short delay
      setTimeout(() => {
        const mockClients = [
          {
            id: '1',
            ip: '192.168.1.101',
            hostname: 'desktop-win10.local',
            connectedSince: new Date().toLocaleTimeString(),
            packetsReceived: 0
          },
          {
            id: '2',
            ip: '192.168.1.105',
            hostname: 'macbook-pro.local',
            connectedSince: new Date().toLocaleTimeString(),
            packetsReceived: 0
          }
        ];
        setConnectedClients(mockClients);
        
        toast({
          title: "New connection",
          description: `Agent ${mockClients[0].hostname} connected`,
        });
        
        // Another client connects after a delay
        setTimeout(() => {
          toast({
            title: "New connection",
            description: `Agent ${mockClients[1].hostname} connected`,
          });
        }, 3000);
      }, 2000);
    } else {
      // Stop the server
      setServerStartTime(null);
      setConnectedClients([]);
      
      toast({
        title: "Server stopped",
        description: `Server has been stopped. Processed ${totalPacketsReceived} packets.`,
      });
    }
  };
  
  // Update server uptime
  useEffect(() => {
    if (isServerRunning && serverStartTime) {
      const interval = setInterval(() => {
        const now = new Date();
        const diff = now.getTime() - serverStartTime.getTime();
        
        const hours = Math.floor(diff / (1000 * 60 * 60));
        const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
        const seconds = Math.floor((diff % (1000 * 60)) / 1000);
        
        setServerUptime(
          `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`
        );
      }, 1000);
      
      return () => clearInterval(interval);
    }
  }, [isServerRunning, serverStartTime]);
  
  // Simulate receiving packets
  useEffect(() => {
    if (isServerRunning && connectedClients.length > 0) {
      const interval = setInterval(() => {
        // Generate 1-3 new packets
        const count = Math.floor(Math.random() * 3) + 1;
        const newPackets = generateMockPackets(count);
        
        // Assign each packet to a random client
        newPackets.forEach(packet => {
          const clientIndex = Math.floor(Math.random() * connectedClients.length);
          
          // Update the client's packet count
          setConnectedClients(prev => {
            const updated = [...prev];
            updated[clientIndex] = {
              ...updated[clientIndex],
              packetsReceived: updated[clientIndex].packetsReceived + 1
            };
            return updated;
          });
        });
        
        setPackets(prev => [...newPackets, ...prev.slice(0, 997)].slice(0, 1000));
        setTotalPacketsReceived(prev => prev + newPackets.length);
        
      }, 1000);
      
      return () => clearInterval(interval);
    }
  }, [isServerRunning, connectedClients]);
  
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Server Controls */}
        <Card className="bg-cyber-dark border-cyber-gray md:col-span-2">
          <CardHeader className="pb-3">
            <CardTitle className="text-lg flex items-center">
              <Database className="mr-2 h-5 w-5" /> 
              Server Controls
            </CardTitle>
            <CardDescription>
              Configure and manage the central packet collection server
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex space-x-2">
              <div className="w-40">
                <Input 
                  placeholder="Listening Port" 
                  value={serverPort} 
                  onChange={(e) => setServerPort(e.target.value)}
                  className="bg-cyber-darker border-cyber-gray"
                  disabled={isServerRunning}
                />
              </div>
              <Button 
                onClick={handleServerToggle}
                variant={isServerRunning ? "destructive" : "default"}
                className={isServerRunning ? "" : "bg-cyber-green hover:bg-cyber-green-light"}
              >
                {isServerRunning ? (
                  <><Pause className="mr-2 h-4 w-4" /> Stop Server</>
                ) : (
                  <><Play className="mr-2 h-4 w-4" /> Start Server</>
                )}
              </Button>
              <Button 
                variant="outline" 
                disabled={packets.length === 0}
                className="border-cyber-blue text-cyber-blue-light"
                onClick={() => {
                  toast({
                    title: "Export not implemented",
                    description: "This would export the captured packets to a file."
                  });
                }}
              >
                <DownloadCloud className="mr-2 h-4 w-4" /> Export
              </Button>
            </div>
          </CardContent>
        </Card>
        
        {/* Server Status */}
        <ServerStatusCard 
          isRunning={isServerRunning}
          port={Number(serverPort)}
          connectedClients={connectedClients}
          totalPacketsReceived={totalPacketsReceived}
          uptime={serverUptime}
        />
      </div>
      
      {/* Received Packets Table */}
      <div className="bg-cyber-dark border border-cyber-gray rounded-md p-4">
        <h2 className="text-lg font-medium mb-4">Received Packets</h2>
        <div className="h-[400px] overflow-y-auto">
          <PacketTable 
            packets={packets} 
            onSelectPacket={setSelectedPacket} 
          />
        </div>
      </div>
      
      <PacketDetails packet={selectedPacket} />
      
      <div className="bg-cyber-darker rounded-md p-4 border border-cyber-gray">
        <h2 className="text-lg font-medium mb-2">Implementation Notes</h2>
        <div className="text-sm text-muted-foreground space-y-2">
          <p>
            This is a mock-up interface to demonstrate the packet capture agent. In a real 
            implementation, this would use platform-specific libraries to capture actual network 
            packets.
          </p>
          <p>
            <strong>Potential Implementation Options:</strong>
          </p>
          <ul className="list-disc pl-5 space-y-1">
            <li>Use <code className="bg-cyber-dark px-1 rounded">libpcap</code> for Unix/Linux/macOS systems</li>
            <li>Use <code className="bg-cyber-dark px-1 rounded">WinPcap/Npcap</code> for Windows systems</li>
            <li>Package the app using Electron to access native system functions</li>
            <li>Implement the packet capture module in Go, Rust or C++ and integrate it with the UI</li>
            <li>For production, implement authentication, encryption, and compression for the client-server communication</li>
          </ul>
        </div>
      </div>
    </div>
  );
};
