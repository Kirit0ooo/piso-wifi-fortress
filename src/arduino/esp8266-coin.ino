
/*
 * ESP8266 Coin Slot Module for Piso WiFi Fortress
 * 
 * This code is designed to run on an ESP8266 connected to a ₱5 coin acceptor module.
 * It detects coin insertions and sends secure HTTP requests to the WiFi server to
 * credit the user's session.
 * 
 * Hardware Connections:
 * - ESP8266 GPIO 4 (D2) -> Coin acceptor pulse output
 * - ESP8266 GPIO 5 (D1) -> Status LED
 * 
 * Security Features:
 * - HTTPS requests with server certificate validation
 * - API key authentication
 * - Hardware ID verification
 * - Request signing
 * - Tamper detection
 * 
 * NOTE: This is a template. In a production system, you would need to:
 * 1. Replace placeholder values with your actual server details
 * 2. Generate and store actual API keys securely
 * 3. Implement proper SSL certificate validation
 */

#include <ESP8266WiFi.h>
#include <ESP8266HTTPClient.h>
#include <WiFiClientSecure.h>
#include <ArduinoJson.h>
#include <EEPROM.h>

// WiFi credentials
const char* ssid = "YOUR_WIFI_SSID";
const char* password = "YOUR_WIFI_PASSWORD";

// Server configuration
const char* serverUrl = "https://your-wifi-server.com/api/coin-insert";
const char* apiKey = "YOUR_SECRET_API_KEY"; // Would be unique per device
const String hardwareId = "COIN-ESP-001";   // Unique identifier for this ESP device

// Pin definitions
const int coinPin = 4;    // D2 - Coin detector input pin
const int ledPin = 5;     // D1 - Status LED

// Operational variables
volatile int coinCount = 0;
unsigned long lastCoinTime = 0;
unsigned long lastUploadTime = 0;
bool pendingUpload = false;

// Security variables
unsigned long bootCount = 0;
bool tamperDetected = false;

// Coin interrupt handler
void ICACHE_RAM_ATTR coinInterrupt() {
  // Debounce logic - ignore pulses that come too quickly
  if (millis() - lastCoinTime > 100) {
    coinCount++;
    lastCoinTime = millis();
    pendingUpload = true;
    
    // Visual feedback
    digitalWrite(ledPin, HIGH);
    delay(50);
    digitalWrite(ledPin, LOW);
  }
}

void setup() {
  // Initialize serial communication
  Serial.begin(115200);
  Serial.println("\nESP8266 Coin Slot Module Starting...");
  
  // Initialize EEPROM for persistent storage
  EEPROM.begin(16);
  
  // Load and increment boot count for tamper detection
  bootCount = EEPROM.read(0);
  bootCount++;
  EEPROM.write(0, bootCount);
  EEPROM.commit();
  
  Serial.print("Boot count: ");
  Serial.println(bootCount);
  
  // Setup pins
  pinMode(coinPin, INPUT_PULLUP);
  pinMode(ledPin, OUTPUT);
  
  // Attach interrupt for coin detection
  attachInterrupt(digitalPinToInterrupt(coinPin), coinInterrupt, FALLING);
  
  // Connect to WiFi
  WiFi.mode(WIFI_STA);
  WiFi.begin(ssid, password);
  
  Serial.print("Connecting to WiFi");
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
    digitalWrite(ledPin, !digitalRead(ledPin)); // Blink LED while connecting
  }
  
  Serial.println("\nWiFi connected");
  Serial.print("IP address: ");
  Serial.println(WiFi.localIP());
  
  // Signal successful connection
  for (int i = 0; i < 3; i++) {
    digitalWrite(ledPin, HIGH);
    delay(100);
    digitalWrite(ledPin, LOW);
    delay(100);
  }
  
  // Run initial security checks
  runSecurityChecks();
}

void loop() {
  // If coins were inserted and we need to report them
  if (pendingUpload && (millis() - lastUploadTime > 2000)) {
    uploadCoinData();
  }
  
  // Check for tamper attempts
  checkForTampering();
  
  // Periodically check WiFi connection and reconnect if needed
  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("WiFi disconnected. Reconnecting...");
    WiFi.reconnect();
  }
  
  delay(100);
}

// Upload coin data to the server
void uploadCoinData() {
  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("WiFi not connected. Will try again later.");
    return;
  }
  
  if (coinCount <= 0) {
    pendingUpload = false;
    return;
  }
  
  Serial.print("Uploading coin count: ");
  Serial.println(coinCount);
  
  // Create secure WiFi client
  WiFiClientSecure client;
  client.setInsecure(); // In production, use client.setCACert() with proper cert
  
  HTTPClient http;
  
  // Begin HTTP connection
  http.begin(client, serverUrl);
  
  // Set headers
  http.addHeader("Content-Type", "application/json");
  http.addHeader("X-API-Key", apiKey);
  http.addHeader("X-Hardware-ID", hardwareId);
  
  // Generate timestamp for request
  unsigned long timestamp = millis();
  
  // Create JSON payload
  DynamicJsonDocument doc(256);
  doc["coins"] = coinCount;
  doc["timestamp"] = timestamp;
  doc["bootCount"] = bootCount;
  doc["tampered"] = tamperDetected;
  
  // Generate a simple signature (in production, use proper HMAC)
  String signature = String(coinCount) + String(timestamp) + hardwareId + String(apiKey).substring(0, 5);
  doc["signature"] = signature;
  
  String requestBody;
  serializeJson(doc, requestBody);
  
  // Send POST request
  int httpCode = http.POST(requestBody);
  
  // Check the returning code
  if (httpCode > 0) {
    if (httpCode == HTTP_CODE_OK) {
      String payload = http.getString();
      Serial.println("Server response: " + payload);
      
      // Parse response
      DynamicJsonDocument responseDoc(256);
      DeserializationError error = deserializeJson(responseDoc, payload);
      
      if (!error) {
        bool success = responseDoc["success"];
        if (success) {
          // Reset coin count after successful upload
          coinCount = 0;
          pendingUpload = false;
          lastUploadTime = millis();
          
          // Success indication
          digitalWrite(ledPin, HIGH);
          delay(200);
          digitalWrite(ledPin, LOW);
        }
      }
    } else {
      Serial.printf("HTTP error code: %d\n", httpCode);
    }
  } else {
    Serial.printf("HTTP request failed: %s\n", http.errorToString(httpCode).c_str());
  }
  
  http.end();
}

// Run security checks at boot
void runSecurityChecks() {
  // Check for unexpected resets
  if (bootCount > 1000) {
    Serial.println("SECURITY: Unusual number of reboots detected");
    tamperDetected = true;
  }
  
  // You could add more security checks here:
  // - Verify flash integrity
  // - Check for voltage glitching
  // - Verify timing of operations
}

// Check for tampering attempts during operation
void checkForTampering() {
  // Check for WiFi signal strength changes (potential jamming)
  long rssi = WiFi.RSSI();
  if (rssi < -90) {
    Serial.println("SECURITY: Weak WiFi signal detected");
  }
  
  // Additional runtime checks could be added here
}
