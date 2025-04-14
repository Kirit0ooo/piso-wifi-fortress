
import React from "react";
import { useWifi } from "@/contexts/WifiContext";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import { Coins, Clock, Loader } from "lucide-react";
import { simulateCoinInsertion } from "@/lib/utils";

const CoinSlotLogin: React.FC = () => {
  const { 
    coinsInserted, 
    setCoinsInserted, 
    loginWithCoins, 
    userStatus 
  } = useWifi();
  
  const handleInsertCoin = () => {
    simulateCoinInsertion(coinsInserted, setCoinsInserted);
  };
  
  const calculateMinutes = () => {
    return coinsInserted * 25; // ₱5 = 25 minutes
  };
  
  const handleConnectClick = async () => {
    await loginWithCoins();
  };
  
  return (
    <div className="space-y-4">
      <Card className="p-4 bg-white border border-gray-100">
        <div className="flex items-center justify-between">
          <div className="flex items-center">
            <Coins className="text-yellow-500 mr-2" size={20} />
            <span className="font-medium text-gray-700">Coins Inserted</span>
          </div>
          <div className="text-lg font-bold text-wifi-primary">
            ₱{coinsInserted * 5}
          </div>
        </div>
        
        <Separator className="my-2" />
        
        <div className="flex items-center justify-between">
          <div className="flex items-center">
            <Clock className="text-wifi-primary mr-2" size={20} />
            <span className="font-medium text-gray-700">Time Credit</span>
          </div>
          <div className="text-lg font-bold text-wifi-primary">
            {calculateMinutes()} minutes
          </div>
        </div>
      </Card>
      
      <div className="flex flex-col space-y-3">
        {/* Demo buttons for coin insertion - in the real implementation, 
            this would be triggered by the ESP8266 hardware */}
        <Button 
          type="button"
          variant="outline"
          onClick={handleInsertCoin}
          className="border-yellow-500 text-yellow-600 hover:bg-yellow-50"
          disabled={userStatus === "connecting"}
        >
          <Coins className="mr-2" size={16} />
          Insert ₱5 Coin (Demo Only)
        </Button>
        
        <Button 
          type="button" 
          className="w-full wifi-gradient hover:opacity-90 transition-opacity"
          disabled={userStatus === "connecting" || coinsInserted === 0}
          onClick={handleConnectClick}
        >
          {userStatus === "connecting" ? (
            <>
              <Loader className="mr-2 h-4 w-4 animate-spin" />
              Connecting...
            </>
          ) : (
            "Connect to WiFi"
          )}
        </Button>
      </div>
      
      <div className="text-center text-xs text-gray-500">
        Rate: ₱5 = 25 minutes of high-speed internet
      </div>
    </div>
  );
};

export default CoinSlotLogin;
