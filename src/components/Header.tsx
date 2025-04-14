
import React from "react";
import { useWifi } from "@/contexts/WifiContext";
import { Button } from "@/components/ui/button";
import { Wifi, WifiOff, ShieldCheck } from "lucide-react";

const Header: React.FC = () => {
  const { userStatus, logout } = useWifi();
  
  return (
    <header className="w-full bg-white shadow-sm py-4 px-6 flex justify-between items-center">
      <div className="flex items-center space-x-2">
        <div className="wifi-gradient p-2 rounded-full">
          {userStatus === "authenticated" ? (
            <Wifi size={20} className="text-white" />
          ) : (
            <WifiOff size={20} className="text-white" />
          )}
        </div>
        <div>
          <h1 className="text-xl font-bold text-wifi-primary">
            Piso WiFi Fortress
          </h1>
          <p className="text-xs text-gray-500">
            High Security WiFi System
          </p>
        </div>
      </div>

      <div className="flex items-center">
        <div className="hidden md:flex items-center mr-4">
          <ShieldCheck size={18} className="text-green-600 mr-2" />
          <span className="text-sm text-gray-600">Fort Knox Security</span>
        </div>
        
        {userStatus === "authenticated" && (
          <Button 
            variant="outline" 
            size="sm" 
            onClick={logout}
            className="border-wifi-primary text-wifi-primary hover:bg-wifi-light"
          >
            Disconnect
          </Button>
        )}
      </div>
    </header>
  );
};

export default Header;
