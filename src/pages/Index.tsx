
import React from "react";
import { WifiProvider } from "@/contexts/WifiContext";
import { useWifi } from "@/contexts/WifiContext";
import Header from "@/components/Header";
import Footer from "@/components/Footer";
import AuthMethods from "@/components/AuthMethods";
import ActiveSession from "@/components/ActiveSession";

const IndexContent: React.FC = () => {
  const { userStatus } = useWifi();
  
  return (
    <div className="min-h-screen flex flex-col bg-gray-100">
      <Header />
      
      <main className="flex-1 container mx-auto py-8 px-4 flex flex-col items-center justify-center">
        {userStatus === "authenticated" ? (
          <ActiveSession />
        ) : (
          <>
            <div className="text-center mb-8">
              <h1 className="text-3xl font-bold text-wifi-dark mb-2">
                Welcome to Piso WiFi Fortress
              </h1>
              <p className="text-gray-600 max-w-lg mx-auto">
                Connect to our high-speed, secure WiFi network using vouchers or coins.
                Enjoy a fast and protected internet experience.
              </p>
            </div>
            <AuthMethods />
          </>
        )}
      </main>
      
      <Footer />
    </div>
  );
};

const Index: React.FC = () => {
  return (
    <WifiProvider>
      <IndexContent />
    </WifiProvider>
  );
};

export default Index;
