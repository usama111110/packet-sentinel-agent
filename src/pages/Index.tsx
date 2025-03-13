
import React, { useState, useEffect } from 'react';
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { AgentPage } from "@/pages/AgentPage";
import { ServerPage } from "@/pages/ServerPage";

const Index = () => {
  return (
    <div className="min-h-screen flex flex-col bg-cyber-darker text-foreground">
      <header className="bg-cyber-dark border-b border-cyber-gray p-4">
        <div className="container flex justify-between items-center">
          <div className="flex items-center space-x-2">
            <div className="w-8 h-8 rounded-full bg-cyber-blue animate-pulse-glow flex items-center justify-center">
              <div className="w-4 h-4 rounded-full bg-cyber-blue-light"></div>
            </div>
            <h1 className="text-xl font-bold">Packet Sentinel</h1>
          </div>
          <div className="text-sm text-cyber-gray">
            Cross-platform Network Monitoring Agent
          </div>
        </div>
      </header>
      
      <main className="flex-1 container py-6">
        <Tabs defaultValue="agent" className="space-y-4">
          <TabsList className="grid w-full max-w-md mx-auto grid-cols-2 bg-cyber-dark">
            <TabsTrigger value="agent">Agent Mode</TabsTrigger>
            <TabsTrigger value="server">Server Mode</TabsTrigger>
          </TabsList>
          
          <TabsContent value="agent" className="space-y-4">
            <AgentPage />
          </TabsContent>
          
          <TabsContent value="server" className="space-y-4">
            <ServerPage />
          </TabsContent>
        </Tabs>
      </main>
      
      <footer className="bg-cyber-dark border-t border-cyber-gray p-3 text-center text-xs text-cyber-gray">
        <div className="container">
          Packet Sentinel Agent v1.0.0 | Cross-platform Network Monitoring Tool
        </div>
      </footer>
    </div>
  );
};

export default Index;
