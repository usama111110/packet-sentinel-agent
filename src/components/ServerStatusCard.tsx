
import React from 'react';
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";

interface ConnectedClient {
  id: string;
  ip: string;
  hostname: string;
  connectedSince: string;
  packetsReceived: number;
}

interface ServerStatusCardProps {
  isRunning: boolean;
  port: number;
  connectedClients: ConnectedClient[];
  totalPacketsReceived: number;
  uptime: string;
}

const ServerStatusCard: React.FC<ServerStatusCardProps> = ({
  isRunning,
  port,
  connectedClients,
  totalPacketsReceived,
  uptime
}) => {
  return (
    <Card className="bg-cyber-dark border-border">
      <CardHeader className="flex flex-row items-center justify-between pb-2">
        <CardTitle className="text-lg">Server Status</CardTitle>
        {isRunning ? (
          <Badge className="bg-cyber-green text-white">Running</Badge>
        ) : (
          <Badge className="bg-cyber-gray text-white">Stopped</Badge>
        )}
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid grid-cols-2 gap-4">
          <div>
            <p className="text-sm text-muted-foreground">Listening Port</p>
            <p className="font-medium">{port}</p>
          </div>
          <div>
            <p className="text-sm text-muted-foreground">Uptime</p>
            <p className="font-medium">{uptime}</p>
          </div>
          <div>
            <p className="text-sm text-muted-foreground">Connected Clients</p>
            <p className="font-medium">{connectedClients.length}</p>
          </div>
          <div>
            <p className="text-sm text-muted-foreground">Total Packets</p>
            <p className="font-medium">{totalPacketsReceived}</p>
          </div>
        </div>
        
        <div>
          <p className="text-sm text-muted-foreground mb-2">Client Connections</p>
          <div className="bg-cyber-darker rounded-md p-2 max-h-[150px] overflow-y-auto">
            {connectedClients.length > 0 ? (
              <div className="space-y-2">
                {connectedClients.map(client => (
                  <div key={client.id} className="flex justify-between items-center text-xs p-1 border-b border-border last:border-0">
                    <div>
                      <div className="font-medium">{client.hostname}</div>
                      <div className="text-muted-foreground font-mono">{client.ip}</div>
                    </div>
                    <div className="text-right">
                      <div>{client.packetsReceived} packets</div>
                      <div className="text-muted-foreground">Since {client.connectedSince}</div>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-center text-muted-foreground text-sm py-2">
                No clients connected
              </p>
            )}
          </div>
        </div>
      </CardContent>
    </Card>
  );
};

export default ServerStatusCard;
