
import React, { createContext, useState, useContext, ReactNode } from "react";
import { useToast } from "@/components/ui/use-toast";

export type AuthMethod = "voucher" | "coinslot" | "none";
export type UserStatus = "authenticated" | "unauthenticated" | "connecting";

interface WifiContextProps {
  authMethod: AuthMethod;
  userStatus: UserStatus;
  sessionTime: number; // in seconds
  voucherCode: string;
  coinsInserted: number;
  macAddress: string;
  ipAddress: string;
  remainingTime: number; // in seconds
  usedData: number; // in bytes
  
  setAuthMethod: (method: AuthMethod) => void;
  setUserStatus: (status: UserStatus) => void;
  setSessionTime: (time: number) => void;
  setVoucherCode: (code: string) => void;
  setCoinsInserted: (coins: number) => void;
  setMacAddress: (mac: string) => void;
  setIpAddress: (ip: string) => void;
  setRemainingTime: (time: number) => void;
  setUsedData: (data: number) => void;
  
  loginWithVoucher: (code: string) => Promise<boolean>;
  loginWithCoins: () => Promise<boolean>;
  logout: () => void;
}

const WifiContext = createContext<WifiContextProps | undefined>(undefined);

export const WifiProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const { toast } = useToast();

  // State variables
  const [authMethod, setAuthMethod] = useState<AuthMethod>("none");
  const [userStatus, setUserStatus] = useState<UserStatus>("unauthenticated");
  const [sessionTime, setSessionTime] = useState(0);
  const [voucherCode, setVoucherCode] = useState("");
  const [coinsInserted, setCoinsInserted] = useState(0);
  const [macAddress, setMacAddress] = useState("");
  const [ipAddress, setIpAddress] = useState("");
  const [remainingTime, setRemainingTime] = useState(0);
  const [usedData, setUsedData] = useState(0);

  // Mock API calls
  const loginWithVoucher = async (code: string): Promise<boolean> => {
    // Simulate API call
    setUserStatus("connecting");
    
    try {
      // This would be a real API call in production
      await new Promise(resolve => setTimeout(resolve, 2000));
      
      // Mock validation
      if (code === "FREE123" || code === "TEST456") {
        // Get client info
        const mockMac = "AA:BB:CC:DD:EE:FF"; // This would be detected in production
        const mockIp = "192.168.1.100"; // This would be detected in production
        
        setMacAddress(mockMac);
        setIpAddress(mockIp);
        setUserStatus("authenticated");
        setAuthMethod("voucher");
        
        // Set session time based on voucher (minutes * 60 seconds)
        const mockSessionTime = code === "FREE123" ? 60 * 60 : 120 * 60; // 1hr or 2hrs
        setSessionTime(mockSessionTime);
        setRemainingTime(mockSessionTime);
        
        toast({
          title: "Login Successful",
          description: `Your voucher has been accepted. You have ${mockSessionTime / 60} minutes of access.`,
        });
        
        // Start countdown timer
        startSessionTimer();
        
        return true;
      } else {
        setUserStatus("unauthenticated");
        toast({
          title: "Invalid Voucher",
          description: "The voucher code you entered is invalid or expired.",
          variant: "destructive",
        });
        return false;
      }
    } catch (error) {
      setUserStatus("unauthenticated");
      toast({
        title: "Connection Error",
        description: "Unable to validate your voucher. Please try again.",
        variant: "destructive",
      });
      return false;
    }
  };
  
  const loginWithCoins = async (): Promise<boolean> => {
    // In a real implementation, this would be triggered by the ESP8266
    // sending a POST request to the server
    
    setUserStatus("connecting");
    
    try {
      // This would be a real API call in production
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      // Calculate time based on coins (₱5 = 25 mins)
      const totalMinutes = coinsInserted * 5;
      const seconds = totalMinutes * 60;
      
      if (coinsInserted > 0) {
        // Get client info
        const mockMac = "AA:BB:CC:DD:EE:FF"; // This would be detected in production
        const mockIp = "192.168.1.100"; // This would be detected in production
        
        setMacAddress(mockMac);
        setIpAddress(mockIp);
        setUserStatus("authenticated");
        setAuthMethod("coinslot");
        setSessionTime(seconds);
        setRemainingTime(seconds);
        
        toast({
          title: "Coins Accepted",
          description: `You have inserted ₱${coinsInserted * 5}. You have ${totalMinutes} minutes of access.`,
        });
        
        // Start countdown timer
        startSessionTimer();
        
        return true;
      } else {
        setUserStatus("unauthenticated");
        toast({
          title: "No Coins Inserted",
          description: "Please insert coins to continue.",
          variant: "destructive",
        });
        return false;
      }
    } catch (error) {
      setUserStatus("unauthenticated");
      toast({
        title: "Connection Error",
        description: "Unable to process your payment. Please try again.",
        variant: "destructive",
      });
      return false;
    }
  };
  
  const logout = () => {
    // Reset all session data
    setAuthMethod("none");
    setUserStatus("unauthenticated");
    setSessionTime(0);
    setVoucherCode("");
    setCoinsInserted(0);
    setRemainingTime(0);
    setUsedData(0);
    
    toast({
      title: "Logged Out",
      description: "You have been disconnected from the WiFi network.",
    });
  };
  
  // Timer functionality for session countdown
  const startSessionTimer = () => {
    const intervalId = setInterval(() => {
      setRemainingTime(prev => {
        // Simulate data usage (random between 50KB-500KB per second)
        const dataIncrement = Math.floor(Math.random() * 450000) + 50000;
        setUsedData(prevData => prevData + dataIncrement);
        
        if (prev <= 1) {
          clearInterval(intervalId);
          logout();
          return 0;
        }
        return prev - 1;
      });
    }, 1000);
    
    // Save interval ID for cleanup
    return () => clearInterval(intervalId);
  };
  
  const value: WifiContextProps = {
    authMethod,
    userStatus,
    sessionTime,
    voucherCode,
    coinsInserted,
    macAddress,
    ipAddress,
    remainingTime,
    usedData,
    
    setAuthMethod,
    setUserStatus,
    setSessionTime,
    setVoucherCode,
    setCoinsInserted,
    setMacAddress,
    setIpAddress,
    setRemainingTime,
    setUsedData,
    
    loginWithVoucher,
    loginWithCoins,
    logout,
  };
  
  return <WifiContext.Provider value={value}>{children}</WifiContext.Provider>;
};

export const useWifi = (): WifiContextProps => {
  const context = useContext(WifiContext);
  if (context === undefined) {
    throw new Error("useWifi must be used within a WifiProvider");
  }
  return context;
};
