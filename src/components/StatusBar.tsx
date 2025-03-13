
import React from 'react';

interface StatusBarProps {
  captureStatus: 'idle' | 'capturing' | 'error';
  connectionStatus: 'connected' | 'disconnected' | 'connecting';
  packetCount: number;
  serverAddress: string;
  errorMessage?: string;
}

const StatusBar: React.FC<StatusBarProps> = ({
  captureStatus,
  connectionStatus,
  packetCount,
  serverAddress,
  errorMessage
}) => {
  return (
    <div className="bg-cyber-dark border-t border-border py-2 px-4 flex justify-between items-center text-xs">
      <div className="flex space-x-4">
        <div className="flex items-center">
          <span className="mr-2">Capture Status:</span>
          {captureStatus === 'capturing' ? (
            <div className="flex items-center">
              <span className="status-indicator status-active"></span>
              <span className="text-cyber-green">Active</span>
            </div>
          ) : captureStatus === 'error' ? (
            <div className="flex items-center">
              <span className="status-indicator status-error"></span>
              <span className="text-cyber-red">Error</span>
            </div>
          ) : (
            <div className="flex items-center">
              <span className="status-indicator status-inactive"></span>
              <span className="text-cyber-gray">Idle</span>
            </div>
          )}
        </div>
        
        <div className="flex items-center">
          <span className="mr-2">Connection:</span>
          {connectionStatus === 'connected' ? (
            <div className="flex items-center">
              <span className="status-indicator status-active"></span>
              <span className="text-cyber-green">Connected to {serverAddress}</span>
            </div>
          ) : connectionStatus === 'connecting' ? (
            <div className="flex items-center">
              <span className="status-indicator status-active"></span>
              <span className="text-cyber-yellow">Connecting...</span>
            </div>
          ) : (
            <div className="flex items-center">
              <span className="status-indicator status-inactive"></span>
              <span className="text-cyber-gray">Disconnected</span>
            </div>
          )}
        </div>
      </div>
      
      <div className="flex space-x-4">
        {errorMessage && (
          <div className="text-cyber-red">{errorMessage}</div>
        )}
        <div>
          <span className="text-cyber-gray mr-2">Packets:</span>
          <span className="font-medium">{packetCount}</span>
        </div>
      </div>
    </div>
  );
};

export default StatusBar;
