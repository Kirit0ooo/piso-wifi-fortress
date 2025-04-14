
import React, { useState } from "react";
import { useWifi } from "@/contexts/WifiContext";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Ticket, Loader } from "lucide-react";

const VoucherLogin: React.FC = () => {
  const { voucherCode, setVoucherCode, loginWithVoucher, userStatus } = useWifi();
  const [error, setError] = useState("");
  
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!voucherCode.trim()) {
      setError("Please enter a voucher code");
      return;
    }
    
    setError("");
    await loginWithVoucher(voucherCode);
  };
  
  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div className="space-y-2">
        <label htmlFor="voucher" className="text-sm font-medium text-gray-700">
          Voucher Code
        </label>
        <Input
          id="voucher"
          type="text"
          placeholder="Enter your voucher code"
          value={voucherCode}
          onChange={(e) => setVoucherCode(e.target.value)}
          className="border-gray-300 focus:border-wifi-primary focus:ring-wifi-primary"
          disabled={userStatus === "connecting"}
        />
        {error && <p className="text-xs text-red-500">{error}</p>}
      </div>
      
      <Card className="p-3 bg-blue-50 border-blue-100">
        <div className="flex gap-2 items-start">
          <Ticket className="text-wifi-primary mt-0.5" size={18} />
          <div className="text-sm text-gray-600">
            <p className="font-medium text-wifi-dark">Sample Vouchers for Testing:</p>
            <p><code className="bg-white px-1.5 py-0.5 rounded text-xs border border-gray-200">FREE123</code> - 1 hour access</p>
            <p><code className="bg-white px-1.5 py-0.5 rounded text-xs border border-gray-200">TEST456</code> - 2 hour access</p>
          </div>
        </div>
      </Card>
      
      <Button 
        type="submit" 
        className="w-full wifi-gradient hover:opacity-90 transition-opacity"
        disabled={userStatus === "connecting"}
      >
        {userStatus === "connecting" ? (
          <>
            <Loader className="mr-2 h-4 w-4 animate-spin" />
            Validating...
          </>
        ) : (
          "Connect"
        )}
      </Button>
    </form>
  );
};

export default VoucherLogin;
