
import React from "react";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import VoucherLogin from "@/components/VoucherLogin";
import CoinSlotLogin from "@/components/CoinSlotLogin";
import { Ticket, Coins } from "lucide-react";

const AuthMethods: React.FC = () => {
  return (
    <div className="w-full max-w-md mx-auto bg-white rounded-lg overflow-hidden shadow-md wifi-shadow">
      <div className="wifi-gradient px-6 py-4 text-white">
        <h2 className="text-xl font-semibold text-center">Connect to WiFi</h2>
        <p className="text-sm text-center opacity-80">Choose your authentication method</p>
      </div>
      
      <Tabs defaultValue="voucher" className="w-full">
        <TabsList className="grid w-full grid-cols-2">
          <TabsTrigger value="voucher" className="flex items-center justify-center gap-2">
            <Ticket size={16} />
            <span>Voucher</span>
          </TabsTrigger>
          <TabsTrigger value="coinslot" className="flex items-center justify-center gap-2">
            <Coins size={16} />
            <span>Coin Slot</span>
          </TabsTrigger>
        </TabsList>
        
        <TabsContent value="voucher" className="p-6">
          <VoucherLogin />
        </TabsContent>
        
        <TabsContent value="coinslot" className="p-6">
          <CoinSlotLogin />
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default AuthMethods;
