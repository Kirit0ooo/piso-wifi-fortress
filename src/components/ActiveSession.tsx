
import React, { useEffect, useState } from "react";
import { useWifi } from "@/contexts/WifiContext";
import { Progress } from "@/components/ui/progress";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Clock, Database, Wifi, ShieldCheck } from "lucide-react";
import { formatTime, formatDataSize } from "@/lib/utils";

const ActiveSession: React.FC = () => {
  const { 
    authMethod, 
    sessionTime, 
    remainingTime, 
    usedData, 
    macAddress, 
    ipAddress,
    logout 
  } = useWifi();
  
  const [progress, setProgress] = useState(100);
  
  // Calculate progress percentage
  useEffect(() => {
    if (sessionTime > 0) {
      setProgress(Math.max(0, Math.min(100, (remainingTime / sessionTime) * 100)));
    }
  }, [remainingTime, sessionTime]);
  
  return (
    <div className="w-full max-w-md mx-auto">
      <Card className="overflow-hidden wifi-shadow">
        <div className="wifi-gradient px-6 py-4 text-white">
          <div className="flex justify-between items-center">
            <h2 className="text-xl font-semibold">Active Session</h2>
            <Wifi size={20} className="animate-pulse-slow" />
          </div>
          <p className="text-sm opacity-80">
            {authMethod === "voucher" ? "Voucher Access" : "Coin Slot Access"}
          </p>
        </div>
        
        <CardHeader className="pb-2">
          <CardDescription className="flex items-center">
            <ShieldCheck className="h-4 w-4 mr-1.5 text-green-600" />
            <span>Secured and Authenticated</span>
          </CardDescription>
        </CardHeader>
        
        <CardContent className="space-y-4">
          <div>
            <div className="flex justify-between mb-1">
              <div className="flex items-center text-sm font-medium">
                <Clock className="h-4 w-4 mr-1.5 text-wifi-primary" />
                Time Remaining
              </div>
              <span className="text-sm font-semibold text-wifi-dark">
                {formatTime(remainingTime)}
              </span>
            </div>
            <Progress value={progress} className="h-2" />
          </div>
          
          <div className="grid grid-cols-2 gap-4">
            <div className="bg-gray-50 p-3 rounded-md">
              <div className="text-xs text-gray-500">Data Used</div>
              <div className="flex items-center mt-1">
                <Database className="h-3.5 w-3.5 mr-1 text-wifi-primary" />
                <span className="font-semibold text-sm">{formatDataSize(usedData)}</span>
              </div>
            </div>
            
            <div className="bg-gray-50 p-3 rounded-md">
              <div className="text-xs text-gray-500">Connection Type</div>
              <div className="flex items-center mt-1">
                <Wifi className="h-3.5 w-3.5 mr-1 text-wifi-primary" />
                <span className="font-semibold text-sm">2.4GHz / 5GHz</span>
              </div>
            </div>
          </div>
          
          <div className="bg-blue-50 rounded-md p-3 text-xs border border-blue-100">
            <div className="mb-1 font-medium text-wifi-dark">Security Information</div>
            <div className="grid grid-cols-[auto_1fr] gap-x-2 gap-y-1">
              <span className="text-gray-500">MAC Address:</span>
              <span className="font-mono">{macAddress}</span>
              <span className="text-gray-500">IP Address:</span>
              <span className="font-mono">{ipAddress}</span>
              <span className="text-gray-500">Session ID:</span>
              <span className="font-mono truncate">S-{Math.random().toString(36).substring(2, 10)}</span>
            </div>
          </div>
        </CardContent>
        
        <CardFooter className="px-6 py-4 bg-gray-50 flex justify-between">
          <div className="text-xs text-gray-600">
            Your session is secure and protected.
          </div>
          <Button
            variant="outline"
            size="sm"
            onClick={logout}
            className="border-wifi-primary text-wifi-primary hover:bg-wifi-light"
          >
            Disconnect
          </Button>
        </CardFooter>
      </Card>
    </div>
  );
};

export default ActiveSession;
