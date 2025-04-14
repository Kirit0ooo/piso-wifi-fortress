
import { clsx, type ClassValue } from "clsx"
import { twMerge } from "tailwind-merge"

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

// Format time function (converts seconds to HH:MM:SS)
export function formatTime(seconds: number): string {
  if (seconds <= 0) return "00:00:00";
  
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const secs = seconds % 60;
  
  return [hours, minutes, secs]
    .map(v => v < 10 ? `0${v}` : v)
    .join(":");
}

// Format data size function (converts bytes to KB, MB, GB)
export function formatDataSize(bytes: number): string {
  if (bytes === 0) return "0 B";
  
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
}

// Generate a mock session token
export function generateSessionToken(): string {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let result = "";
  
  for (let i = 0; i < 32; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  
  return result;
}

// Mock function to detect MAC address
export function detectMacAddress(): string {
  // In a real implementation, this would use the client's actual MAC
  return "AA:BB:CC:DD:EE:FF";
}

// Mock function to detect IP address
export function detectIpAddress(): string {
  // In a real implementation, this would use the client's actual IP
  return "192.168.1.100";
}

// For demo purposes - simulate ₱5 coin insertion
export function simulateCoinInsertion(
  currentCoins: number, 
  setCoins: (n: number) => void
): void {
  setCoins(currentCoins + 1);
}
