
import React, { useState, useEffect } from 'react';
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import { Play, Pause, Send, Settings, HardDrive } from "lucide-react";
import { useToast } from "@/components/ui/use-toast";
import { mockNetworkInterfaces, generateMockPackets } from "@/utils/mock-data";

import NetworkInterfaceSelector from "@/components/NetworkInterfaceSelector";
import PacketTable, { Packet } from "@/components/PacketTable";
import PacketDetails from "@/components/PacketDetails";
import StatusBar from "@/components/StatusBar";
import FilterControls from "@/components/FilterControls";

export const AgentPage: React.FC = () => {
  const { toast } = useToast();
  const [serverAddress, setServerAddress] = useState('127.0.0.1');
  const [serverPort, setServerPort] = useState('8888');
  const [selectedInterface, setSelectedInterface] = useState<string | null>(null);
  const [isCaptureActive, setIsCaptureActive] = useState(false);
  const [isConnected, setIsConnected] = useState(false);
  const [packets, setPackets] = useState<Packet[]>([]);
  const [selectedPacket, setSelectedPacket] = useState<Packet | null>(null);
  const [activeProtocols, setActiveProtocols] = useState<string[]>(['TCP', 'UDP', 'HTTP', 'HTTPS', 'DNS']);
  const [filterQuery, setFilterQuery] = useState('');
  const [errorMessage, setErrorMessage] = useState<string | undefined>(undefined);
  
  // Mock connecting to server
  const handleConnectToggle = () => {
    if (isConnected) {
      setIsConnected(false);
      toast({
        title: "Disconnected from server",
        description: `Connection to ${serverAddress}:${serverPort} closed.`,
      });
    } else {
      setIsConnected(true);
      toast({
        title: "Connected to server",
        description: `Successfully connected to ${serverAddress}:${serverPort}`,
      });
    }
  };
  
  // Mock starting/stopping capture
  const handleCaptureToggle = () => {
    if (!selectedInterface) {
      toast({
        title: "Error starting capture",
        description: "Please select a network interface first.",
        variant: "destructive",
      });
      return;
    }
    
    setIsCaptureActive(!isCaptureActive);
    
    if (!isCaptureActive) {
      toast({
        title: "Capture started",
        description: `Capturing packets on interface: ${selectedInterface}`,
      });
      
      // Clear existing packets when starting a new capture
      setPackets([]);
      setSelectedPacket(null);
    } else {
      toast({
        title: "Capture stopped",
        description: `${packets.length} packets captured.`,
      });
    }
  };
  
  // Mock protocol filtering
  const handleProtocolToggle = (protocol: string, enabled: boolean) => {
    if (enabled) {
      setActiveProtocols(prev => [...prev, protocol]);
    } else {
      setActiveProtocols(prev => prev.filter(p => p !== protocol));
    }
  };
  
  // Handle filter changes
  const handleFilterChange = (filter: string) => {
    setFilterQuery(filter);
    toast({
      title: "Filter applied",
      description: filter ? `Applied filter: ${filter}` : "Filter cleared",
    });
  };
  
  // Generate mock packet data for demo
  useEffect(() => {
    if (isCaptureActive) {
      const interval = setInterval(() => {
        const newPacket = generateMockPackets(1)[0];
        
        // Only add the packet if its protocol is in the active protocols list
        if (activeProtocols.includes(newPacket.protocol)) {
          setPackets(prevPackets => {
            const updatedPackets = [newPacket, ...prevPackets.slice(0, 999)]; // Limit to last 1000 packets
            return updatedPackets;
          });
        }
      }, 500); // Add a new packet every 500ms
      
      return () => clearInterval(interval);
    }
  }, [isCaptureActive, activeProtocols]);
  
  // Apply additional filtering based on query
  const filteredPackets = filterQuery 
    ? packets.filter(packet => 
        packet.source.includes(filterQuery) || 
        packet.destination.includes(filterQuery) ||
        packet.info.toLowerCase().includes(filterQuery.toLowerCase())
      )
    : packets;
  
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Connection Settings */}
        <Card className="bg-cyber-dark border-cyber-gray md:col-span-2">
          <CardHeader className="pb-3">
            <CardTitle className="text-lg flex items-center">
              <HardDrive className="mr-2 h-5 w-5" /> 
              Server Connection
            </CardTitle>
            <CardDescription>
              Configure the central server to forward captured packets
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex space-x-2">
              <div className="flex-1">
                <Input 
                  placeholder="Server Address" 
                  value={serverAddress} 
                  onChange={(e) => setServerAddress(e.target.value)}
                  className="bg-cyber-darker border-cyber-gray"
                />
              </div>
              <div className="w-24">
                <Input 
                  placeholder="Port" 
                  value={serverPort} 
                  onChange={(e) => setServerPort(e.target.value)}
                  className="bg-cyber-darker border-cyber-gray"
                />
              </div>
              <Button 
                onClick={handleConnectToggle}
                variant={isConnected ? "destructive" : "default"}
                className={isConnected ? "" : "bg-cyber-blue hover:bg-cyber-blue-light"}
              >
                {isConnected ? "Disconnect" : "Connect"}
              </Button>
            </div>
          </CardContent>
        </Card>
        
        {/* Capture Controls */}
        <Card className="bg-cyber-dark border-cyber-gray">
          <CardHeader className="pb-3">
            <CardTitle className="text-lg flex items-center">
              <Settings className="mr-2 h-5 w-5" /> 
              Capture Controls
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <NetworkInterfaceSelector 
              interfaces={mockNetworkInterfaces}
              selectedInterface={selectedInterface}
              onSelectInterface={setSelectedInterface}
            />
            
            <div className="flex justify-between">
              <Button 
                onClick={handleCaptureToggle} 
                variant="default"
                className={isCaptureActive 
                  ? "bg-cyber-red hover:bg-red-700" 
                  : "bg-cyber-green hover:bg-cyber-green-light"
                }
              >
                {isCaptureActive ? (
                  <><Pause className="mr-2 h-4 w-4" /> Stop</>
                ) : (
                  <><Play className="mr-2 h-4 w-4" /> Start</>
                )}
              </Button>
              
              <Button 
                variant="outline" 
                disabled={!isConnected || packets.length === 0}
                onClick={() => {
                  toast({
                    title: "Packets forwarded",
                    description: `${packets.length} packets forwarded to server.`,
                  });
                }}
                className="border-cyber-blue text-cyber-blue-light"
              >
                <Send className="mr-2 h-4 w-4" /> Forward 
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>
      
      <FilterControls 
        onFilterChange={handleFilterChange}
        onProtocolToggle={handleProtocolToggle}
        activeProtocols={activeProtocols}
      />
      
      <div className="bg-cyber-dark border border-cyber-gray rounded-md">
        <div className="p-4 pb-0">
          <h2 className="text-lg font-medium mb-2">Captured Packets</h2>
          <Separator className="bg-cyber-gray" />
        </div>
        
        <div className="p-4 h-[400px] overflow-y-auto">
          <PacketTable 
            packets={filteredPackets} 
            onSelectPacket={setSelectedPacket} 
          />
        </div>
      </div>
      
      <PacketDetails packet={selectedPacket} />
      
      <StatusBar 
        captureStatus={isCaptureActive ? 'capturing' : 'idle'}
        connectionStatus={isConnected ? 'connected' : 'disconnected'}
        packetCount={packets.length}
        serverAddress={`${serverAddress}:${serverPort}`}
        errorMessage={errorMessage}
      />
    </div>
  );
};
