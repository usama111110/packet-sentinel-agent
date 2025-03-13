
import React, { useState } from 'react';
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Toggle } from "@/components/ui/toggle";
import { Search, Filter } from "lucide-react";

interface FilterControlsProps {
  onFilterChange: (filter: string) => void;
  onProtocolToggle: (protocol: string, enabled: boolean) => void;
  activeProtocols: string[];
}

const protocols = ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS', 'DNS', 'ARP'];

const FilterControls: React.FC<FilterControlsProps> = ({
  onFilterChange,
  onProtocolToggle,
  activeProtocols
}) => {
  const [filterQuery, setFilterQuery] = useState('');

  const handleFilterChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setFilterQuery(e.target.value);
  };

  const handleFilterSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onFilterChange(filterQuery);
  };

  return (
    <div className="space-y-3">
      <form onSubmit={handleFilterSubmit} className="flex gap-2">
        <div className="relative flex-1">
          <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
          <Input
            type="text"
            placeholder="Filter packets (e.g. ip.addr == 192.168.1.1)"
            className="pl-9 bg-cyber-dark border-cyber-gray"
            value={filterQuery}
            onChange={handleFilterChange}
          />
        </div>
        <Button type="submit" variant="default">Apply</Button>
      </form>
      
      <div>
        <div className="flex items-center gap-2 mb-2">
          <Filter className="h-4 w-4" />
          <span className="text-sm font-medium">Protocol Filters</span>
        </div>
        <div className="flex flex-wrap gap-2">
          {protocols.map(protocol => (
            <Toggle
              key={protocol}
              variant="outline"
              size="sm"
              pressed={activeProtocols.includes(protocol)}
              onPressedChange={(pressed) => onProtocolToggle(protocol, pressed)}
              className={activeProtocols.includes(protocol) ? 'bg-cyber-blue/20 text-cyber-blue-light' : 'bg-cyber-dark'}
            >
              {protocol}
            </Toggle>
          ))}
        </div>
      </div>
    </div>
  );
};

export default FilterControls;
