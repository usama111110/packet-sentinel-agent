
import React from 'react';
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Packet } from './PacketTable';

interface PacketDetailsProps {
  packet: Packet | null;
}

const PacketDetails: React.FC<PacketDetailsProps> = ({ packet }) => {
  if (!packet) {
    return (
      <Card className="bg-cyber-dark border-border h-[300px] flex items-center justify-center">
        <p className="text-muted-foreground">Select a packet to view details</p>
      </Card>
    );
  }

  // Mock packet details for the UI
  const mockHexData = Array.from({ length: 16 }, (_, i) => 
    Array.from({ length: 16 }, (_, j) => 
      ((i * 16) + j).toString(16).padStart(2, '0')
    ).join(' ')
  );

  return (
    <Card className="bg-cyber-dark border-border">
      <CardHeader className="pb-2">
        <CardTitle className="text-lg flex items-center">
          <span className="mr-2">Packet Details</span>
          <span className="text-xs text-muted-foreground">ID: {packet.id}</span>
        </CardTitle>
      </CardHeader>
      <CardContent>
        <Tabs defaultValue="summary">
          <TabsList className="grid w-full grid-cols-3 bg-cyber-darker">
            <TabsTrigger value="summary">Summary</TabsTrigger>
            <TabsTrigger value="headers">Headers</TabsTrigger>
            <TabsTrigger value="raw">Raw Data</TabsTrigger>
          </TabsList>
          
          <TabsContent value="summary" className="mt-4 space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <h4 className="text-sm text-muted-foreground mb-1">Protocol</h4>
                <p className="font-medium">{packet.protocol}</p>
              </div>
              <div>
                <h4 className="text-sm text-muted-foreground mb-1">Time</h4>
                <p className="font-medium">{packet.timestamp}</p>
              </div>
              <div>
                <h4 className="text-sm text-muted-foreground mb-1">Source</h4>
                <p className="font-mono">{packet.source}</p>
              </div>
              <div>
                <h4 className="text-sm text-muted-foreground mb-1">Destination</h4>
                <p className="font-mono">{packet.destination}</p>
              </div>
              <div>
                <h4 className="text-sm text-muted-foreground mb-1">Size</h4>
                <p className="font-medium">{packet.size} bytes</p>
              </div>
            </div>
            <div>
              <h4 className="text-sm text-muted-foreground mb-1">Info</h4>
              <p className="font-medium">{packet.info}</p>
            </div>
          </TabsContent>
          
          <TabsContent value="headers" className="mt-4">
            <div className="bg-cyber-darker p-3 rounded font-mono text-xs space-y-2 max-h-[200px] overflow-y-auto">
              <div className="text-cyber-green-light">--- {packet.protocol} Header ---</div>
              <div><span className="text-cyber-blue-light">Version:</span> 4</div>
              <div><span className="text-cyber-blue-light">Header Length:</span> 20 bytes</div>
              <div><span className="text-cyber-blue-light">Total Length:</span> {packet.size} bytes</div>
              <div><span className="text-cyber-blue-light">Source:</span> {packet.source}</div>
              <div><span className="text-cyber-blue-light">Destination:</span> {packet.destination}</div>
              {packet.protocol === 'TCP' && (
                <>
                  <div className="text-cyber-green-light mt-2">--- TCP Header ---</div>
                  <div><span className="text-cyber-blue-light">Source Port:</span> {packet.source.split(':')[1] || '12345'}</div>
                  <div><span className="text-cyber-blue-light">Destination Port:</span> {packet.destination.split(':')[1] || '80'}</div>
                  <div><span className="text-cyber-blue-light">Sequence Number:</span> 1242533232</div>
                  <div><span className="text-cyber-blue-light">Acknowledgment Number:</span> 1242533546</div>
                  <div><span className="text-cyber-blue-light">Flags:</span> PSH, ACK</div>
                </>
              )}
            </div>
          </TabsContent>
          
          <TabsContent value="raw" className="mt-4">
            <div className="bg-cyber-darker p-3 rounded font-mono text-xs max-h-[200px] overflow-y-auto">
              <div className="grid grid-cols-[80px_1fr] gap-4">
                <div className="text-cyber-gray">Offset</div>
                <div>00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F</div>
                {mockHexData.map((row, i) => (
                  <React.Fragment key={i}>
                    <div className="text-cyber-blue-light">{(i * 16).toString(16).padStart(8, '0')}</div>
                    <div>{row}</div>
                  </React.Fragment>
                ))}
              </div>
            </div>
          </TabsContent>
        </Tabs>
      </CardContent>
    </Card>
  );
};

export default PacketDetails;
