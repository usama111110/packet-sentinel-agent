
import React from 'react';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";

export interface Packet {
  id: string;
  timestamp: string;
  protocol: string;
  source: string;
  destination: string;
  size: number;
  info: string;
}

interface PacketTableProps {
  packets: Packet[];
  onSelectPacket: (packet: Packet) => void;
}

const protocolColors: Record<string, string> = {
  TCP: "bg-cyber-blue text-white",
  UDP: "bg-cyber-green text-white",
  ICMP: "bg-cyber-yellow text-black",
  HTTP: "bg-cyber-blue-light text-black",
  HTTPS: "bg-cyber-green-light text-black",
  DNS: "bg-purple-500 text-white",
  ARP: "bg-orange-500 text-white",
  default: "bg-cyber-gray text-white"
};

const PacketTable: React.FC<PacketTableProps> = ({ packets, onSelectPacket }) => {
  return (
    <div className="border border-border rounded-md overflow-hidden">
      <Table>
        <TableHeader className="bg-cyber-dark">
          <TableRow>
            <TableHead className="w-[180px]">Time</TableHead>
            <TableHead className="w-[100px]">Protocol</TableHead>
            <TableHead className="w-[180px]">Source</TableHead>
            <TableHead className="w-[180px]">Destination</TableHead>
            <TableHead className="w-[80px] text-right">Size</TableHead>
            <TableHead>Info</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {packets.length > 0 ? (
            packets.map((packet) => (
              <TableRow 
                key={packet.id}
                onClick={() => onSelectPacket(packet)}
                className="cursor-pointer hover:bg-cyber-dark/50"
              >
                <TableCell className="font-mono text-xs">{packet.timestamp}</TableCell>
                <TableCell>
                  <Badge className={protocolColors[packet.protocol] || protocolColors.default}>
                    {packet.protocol}
                  </Badge>
                </TableCell>
                <TableCell className="font-mono text-xs">{packet.source}</TableCell>
                <TableCell className="font-mono text-xs">{packet.destination}</TableCell>
                <TableCell className="text-right font-mono text-xs">{packet.size} B</TableCell>
                <TableCell className="truncate max-w-[300px]" title={packet.info}>
                  {packet.info}
                </TableCell>
              </TableRow>
            ))
          ) : (
            <TableRow>
              <TableCell colSpan={6} className="text-center py-4 text-muted-foreground">
                No packets captured yet. Start capture to see network traffic.
              </TableCell>
            </TableRow>
          )}
        </TableBody>
      </Table>
    </div>
  );
};

export default PacketTable;
