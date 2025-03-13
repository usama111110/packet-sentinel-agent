
import React from 'react';
import { 
  Select, 
  SelectContent, 
  SelectGroup, 
  SelectItem, 
  SelectLabel, 
  SelectTrigger, 
  SelectValue 
} from "@/components/ui/select";

interface NetworkInterface {
  id: string;
  name: string;
  description: string;
}

interface NetworkInterfaceSelectorProps {
  interfaces: NetworkInterface[];
  selectedInterface: string | null;
  onSelectInterface: (id: string) => void;
  disabled?: boolean;
}

const NetworkInterfaceSelector: React.FC<NetworkInterfaceSelectorProps> = ({
  interfaces,
  selectedInterface,
  onSelectInterface,
  disabled = false
}) => {
  return (
    <div className="space-y-2">
      <label className="block text-sm font-medium text-foreground">Network Interface</label>
      <Select 
        value={selectedInterface || undefined} 
        onValueChange={onSelectInterface}
        disabled={disabled}
      >
        <SelectTrigger className="w-full bg-cyber-dark border-cyber-gray">
          <SelectValue placeholder="Select network interface" />
        </SelectTrigger>
        <SelectContent>
          <SelectGroup>
            <SelectLabel>Available Interfaces</SelectLabel>
            {interfaces.map((netInterface) => (
              <SelectItem key={netInterface.id} value={netInterface.id}>
                <div className="flex flex-col">
                  <span>{netInterface.name}</span>
                  <span className="text-xs text-muted-foreground">{netInterface.description}</span>
                </div>
              </SelectItem>
            ))}
          </SelectGroup>
        </SelectContent>
      </Select>
    </div>
  );
};

export default NetworkInterfaceSelector;
