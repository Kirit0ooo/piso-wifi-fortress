
import React from "react";
import { ShieldCheck, Info, User } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";

const Footer: React.FC = () => {
  return (
    <footer className="mt-auto w-full bg-gray-50 border-t py-4 px-6">
      <div className="flex flex-col md:flex-row justify-between items-center gap-2">
        <div className="flex items-center text-gray-500 text-xs">
          <ShieldCheck className="h-4 w-4 mr-1.5 text-green-600" />
          <span>Secured by Piso WiFi Fortress v1.0</span>
        </div>
        
        <div className="flex items-center gap-2">
          <Tooltip>
            <TooltipTrigger asChild>
              <Button variant="outline" size="icon" className="h-8 w-8 text-gray-500">
                <Info className="h-4 w-4" />
              </Button>
            </TooltipTrigger>
            <TooltipContent>
              <p>About Piso WiFi Fortress</p>
            </TooltipContent>
          </Tooltip>
          
          <Tooltip>
            <TooltipTrigger asChild>
              <Button variant="outline" size="icon" className="h-8 w-8 text-gray-500">
                <User className="h-4 w-4" />
              </Button>
            </TooltipTrigger>
            <TooltipContent>
              <p>Admin Login</p>
            </TooltipContent>
          </Tooltip>
        </div>
      </div>
    </footer>
  );
};

export default Footer;
