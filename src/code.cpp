#include <Arduino.h>
#include <Adafruit_Fingerprint.h>
#include <Preferences.h>
#include <WiFi.h>
#include <WiFiUdp.h>
#include <esp_wifi.h>
#include "mbedtls/aes.h"

// =====================
// Wi-Fi Hotspot (SoftAP) Config
// =====================
const char* AP_SSID = "ESP32-Fingerprint-AP";
const char* AP_PASS = "password123";
const IPAddress AP_LOCAL_IP(192, 168, 4, 1);
const IPAddress AP_GATEWAY(192, 168, 4, 1);
const IPAddress AP_SUBNET(255, 255, 255, 0);

WiFiServer httpServer(80);
WiFiUDP udpSender;

String latestAuthFilename = "auth_false.enc";
String latestAuthHex = "";

// =====================
// Hardware Configuration
// =====================
HardwareSerial FingerSerial(2);              // UART2
Adafruit_Fingerprint finger(&FingerSerial);

// =====================
// LED Configuration
// =====================
const uint8_t LED_RED_PIN   = 4;   // D4 - Red LED   (verification failed)
const uint8_t LED_GREEN_PIN = 2;   // D2 - Green LED (verification success)

// =====================
// Pushbutton Configuration (GPIO 34)
// =====================
const uint8_t BUTTON_PIN = 34;   // Pushbutton pin on GPIO 34 (Input only pin)
int lastButtonState = HIGH;
unsigned long lastDebounceTime = 0;
const unsigned long debounceDelay = 50;

// =====================
// Encryption Configuration (AES-128-CBC)
// =====================
const uint8_t AES_KEY[16] = {'M', 'y', 'S', 'e', 'c', 'r', '3', 't', 'A', 'E', 'S', 'K', 'e', 'y', '!', '!'};
const uint8_t AES_IV[16]  = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};

// =====================
// Persistent Storage (NVS)
// =====================
Preferences prefs;
const char* PREFS_NAMESPACE = "fp_names";
const uint16_t MAX_ID = 127;

// =====================
// State Variables
// =====================
bool isEnrolling = false;

// =====================
// Function Prototypes
// =====================
void setupWiFiAP();
void handleHTTPClientRequests();
void saveName(uint16_t id, const String& name);
String loadName(uint16_t id);
void deleteName(uint16_t id);
void ledsOff();
void showSuccess();
void showFailure();

void processSerialCommand(const String& cmd);
void checkFingerprintContinuous();
void checkButtonTrigger();
void triggerPushbuttonAuthScan();
void enrollFingerprintProcess(uint16_t id, const String& name);

String encryptAES128Hex(const String& plaintext);
void sendAuthFileToConnectedDevices(bool isSuccess, uint16_t id = 0, const String& name = "");
bool sendHTTPPostAuthFile(const IPAddress& targetIP, uint16_t port, const String& filename, const String& contentHex);

// =====================
// Setup
// =====================
void setup() {
  Serial.begin(115200);
  delay(1000);

  // LED Pins
  pinMode(LED_RED_PIN, OUTPUT);
  pinMode(LED_GREEN_PIN, OUTPUT);
  ledsOff();

  // Pushbutton Pin (GPIO 34)
  pinMode(BUTTON_PIN, INPUT);

  // Initialize Wi-Fi Hotspot
  setupWiFiAP();

  // Initialize Fingerprint Sensor (GPIO 16=RX, 17=TX)
  FingerSerial.begin(57600, SERIAL_8N1, 16, 17);
  finger.begin(57600);

  if (!finger.verifyPassword()) {
    Serial.println("{\"event\":\"error\",\"msg\":\"Fingerprint sensor not found!\"}");
  } else {
    Serial.println("{\"event\":\"ready\",\"msg\":\"AS608 Fingerprint Ready and AP active\"}");
  }

  prefs.begin(PREFS_NAMESPACE, false);
}

// =====================
// Main Loop
// =====================
void loop() {
  // Handle HTTP web requests over Wi-Fi Hotspot
  handleHTTPClientRequests();

  // Check GPIO 34 Pushbutton Trigger
  checkButtonTrigger();

  // Check for incoming serial commands from Python GUI
  if (Serial.available()) {
    String cmd = Serial.readStringUntil('\n');
    cmd.trim();
    if (cmd.length() > 0) {
      processSerialCommand(cmd);
    }
  }

  // Continuous Fingerprint Scanner (when not actively executing serial enroll)
  if (!isEnrolling) {
    checkFingerprintContinuous();
  }

  delay(50);
}

// =====================
// Wi-Fi Hotspot Setup & HTTP Server
// =====================
void setupWiFiAP() {
  WiFi.mode(WIFI_AP);
  WiFi.softAPConfig(AP_LOCAL_IP, AP_GATEWAY, AP_SUBNET);
  bool apSuccess = WiFi.softAP(AP_SSID, AP_PASS);

  if (apSuccess) {
    httpServer.begin();
    Serial.print("{\"event\":\"ap_started\",\"ip\":\"");
    Serial.print(WiFi.softAPIP());
    Serial.println("\"}");
  } else {
    Serial.println("{\"event\":\"error\",\"msg\":\"Failed to start SoftAP\"}");
  }
}

void handleHTTPClientRequests() {
  WiFiClient client = httpServer.available();
  if (client) {
    String req = client.readStringUntil('\r');
    client.flush();

    client.println("HTTP/1.1 200 OK");
    client.println("Content-Type: text/plain");
    client.println("Access-Control-Allow-Origin: *");
    client.println("Connection: close");
    client.println();
    client.println(latestAuthHex);
    client.stop();
  }
}

// =====================
// Process Serial Commands
// =====================
void processSerialCommand(const String& cmd) {
  // Enroll command: e <ID> <Name>
  if (cmd.startsWith("e ")) {
    int firstSpace = cmd.indexOf(' ');
    int secondSpace = cmd.indexOf(' ', firstSpace + 1);

    if (firstSpace != -1) {
      uint16_t id = 0;
      String name = "";

      if (secondSpace != -1) {
        id = cmd.substring(firstSpace + 1, secondSpace).toInt();
        name = cmd.substring(secondSpace + 1);
      } else {
        id = cmd.substring(firstSpace + 1).toInt();
        name = "User_" + String(id);
      }

      if (id > 0 && id <= MAX_ID) {
        isEnrolling = true;
        enrollFingerprintProcess(id, name);
        isEnrolling = false;
      } else {
        Serial.println("{\"event\":\"enroll_status\",\"step\":\"error\",\"msg\":\"Invalid ID (1-127)\"}");
      }
    }
  }
  // Verify command: v
  else if (cmd.equalsIgnoreCase("v")) {
    checkFingerprintContinuous();
  }
  // Delete command: d <ID>
  else if (cmd.startsWith("d ")) {
    uint16_t id = cmd.substring(2).toInt();
    if (id > 0 && finger.deleteModel(id) == FINGERPRINT_OK) {
      deleteName(id);
      Serial.print("{\"event\":\"delete\",\"status\":\"success\",\"id\":");
      Serial.print(id);
      Serial.println("}");
    } else {
      Serial.print("{\"event\":\"delete\",\"status\":\"failed\",\"id\":");
      Serial.print(id);
      Serial.println("}");
    }
  }
  // List command: l
  else if (cmd.equalsIgnoreCase("l")) {
    finger.getTemplateCount();
    Serial.print("{\"event\":\"list\",\"count\":");
    Serial.print(finger.templateCount);
    Serial.print(",\"templates\":[");

    bool first = true;
    for (uint16_t id = 1; id <= MAX_ID; id++) {
      String name = loadName(id);
      if (name.length() > 0 || finger.loadModel(id) == FINGERPRINT_OK) {
        if (name.length() == 0) {
          name = "User #" + String(id);
        }
        if (!first) Serial.print(",");
        first = false;
        Serial.print("{\"id\":");
        Serial.print(id);
        Serial.print(",\"name\":\"");
        Serial.print(name);
        Serial.print("\"}");
      }
    }
    Serial.println("]}");
  }
  // Ping command
  else if (cmd.equalsIgnoreCase("ping")) {
    finger.getTemplateCount();

    wifi_sta_list_t stationList;
    esp_wifi_ap_get_sta_list(&stationList);

    tcpip_adapter_sta_list_t adapterList;
    tcpip_adapter_get_sta_list(&stationList, &adapterList);

    Serial.print("{\"event\":\"pong\",\"ip\":\"");
    Serial.print(WiFi.softAPIP());
    Serial.print("\",\"stations_count\":");
    Serial.print(adapterList.num);
    Serial.print(",\"count\":");
    Serial.print(finger.templateCount);
    Serial.print(",\"stations\":[");

    for (int i = 0; i < adapterList.num; i++) {
      if (i > 0) Serial.print(",");
      
      char macStr[18];
      snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
               adapterList.sta[i].mac[0], adapterList.sta[i].mac[1],
               adapterList.sta[i].mac[2], adapterList.sta[i].mac[3],
               adapterList.sta[i].mac[4], adapterList.sta[i].mac[5]);

      IPAddress staIP(adapterList.sta[i].ip.addr);

      Serial.print("{\"ip\":\"");
      Serial.print(staIP);
      Serial.print("\",\"mac\":\"");
      Serial.print(macStr);
      Serial.print("\"}");
    }

    Serial.println("]}");
  }
}

// =====================
// Continuous Fingerprint Checking
// =====================
void checkFingerprintContinuous() {
  uint8_t p = finger.getImage();

  if (p == FINGERPRINT_NOFINGER) {
    return; // No finger placed
  }

  if (p != FINGERPRINT_OK) {
    return;
  }

  // Convert image
  p = finger.image2Tz();
  if (p != FINGERPRINT_OK) {
    showFailure();
    Serial.println("{\"event\":\"verify\",\"status\":\"failed\",\"reason\":\"image_error\"}");
    sendAuthFileToConnectedDevices(false);
    while (finger.getImage() != FINGERPRINT_NOFINGER) delay(50);
    return;
  }

  // Search template
  p = finger.fingerFastSearch();
  if (p == FINGERPRINT_OK) {
    uint16_t id = finger.fingerID;
    String name = loadName(id);
    if (name.length() == 0) name = "User_" + String(id);

    showSuccess();

    Serial.print("{\"event\":\"verify\",\"status\":\"success\",\"id\":");
    Serial.print(id);
    Serial.print(",\"name\":\"");
    Serial.print(name);
    Serial.print("\",\"confidence\":");
    Serial.print(finger.confidence);
    Serial.println("}");

    // Send encrypted authentication file to connected device via SCP/Socket
    sendAuthFileToConnectedDevices(true, id, name);

  } else {
    showFailure();
    Serial.println("{\"event\":\"verify\",\"status\":\"failed\",\"reason\":\"no_match\"}");

    // Send authentication false file to connected device via SCP/Socket
    sendAuthFileToConnectedDevices(false);
  }

  // Wait for finger to be lifted to avoid duplicate scans
  while (finger.getImage() != FINGERPRINT_NOFINGER) {
    delay(50);
  }
}

// =====================
// GPIO 34 Pushbutton Trigger Handler
// =====================
void checkButtonTrigger() {
  int reading = digitalRead(BUTTON_PIN);

  // Active-low / level change detection with debounce
  if (reading != lastButtonState) {
    lastDebounceTime = millis();
  }

  if ((millis() - lastDebounceTime) > debounceDelay) {
    if (reading == LOW && lastButtonState == HIGH) {
      Serial.println("{\"event\":\"button_press\",\"msg\":\"GPIO 34 Button Pressed! Starting fingerprint authentication scan...\"}");
      triggerPushbuttonAuthScan();
    }
  }

  lastButtonState = reading;
}

void triggerPushbuttonAuthScan() {
  ledsOff();
  Serial.println("{\"event\":\"scan_waiting\",\"msg\":\"Place finger on sensor...\"}");

  unsigned long startTime = millis();
  bool fingerDetected = false;

  // Wait up to 5 seconds for finger placement
  while (millis() - startTime < 5000) {
    if (finger.getImage() == FINGERPRINT_OK) {
      fingerDetected = true;
      break;
    }
    delay(50);
  }

  if (fingerDetected) {
    checkFingerprintContinuous();
  } else {
    Serial.println("{\"event\":\"scan_timeout\",\"msg\":\"No finger placed on sensor within 5 seconds.\"}");
    showFailure();
    sendAuthFileToConnectedDevices(false);
  }
}

// =====================
// Interactive Enrollment Process
// =====================
void enrollFingerprintProcess(uint16_t id, const String& name) {
  ledsOff();

  Serial.println("{\"event\":\"enroll_status\",\"step\":\"place_1\",\"msg\":\"Place finger on sensor...\"}");

  // Scan 1
  while (finger.getImage() != FINGERPRINT_OK) {
    if (Serial.available() && Serial.readStringUntil('\n').equalsIgnoreCase("cancel")) {
      Serial.println("{\"event\":\"enroll_status\",\"step\":\"cancelled\",\"msg\":\"Enrollment cancelled\"}");
      return;
    }
    delay(50);
  }

  if (finger.image2Tz(1) != FINGERPRINT_OK) {
    Serial.println("{\"event\":\"enroll_status\",\"step\":\"error\",\"msg\":\"Image conversion failed\"}");
    showFailure();
    return;
  }

  Serial.println("{\"event\":\"enroll_status\",\"step\":\"remove\",\"msg\":\"Remove finger from sensor...\"}");
  while (finger.getImage() != FINGERPRINT_NOFINGER) delay(50);
  delay(1000);

  Serial.println("{\"event\":\"enroll_status\",\"step\":\"place_2\",\"msg\":\"Place SAME finger again...\"}");
  while (finger.getImage() != FINGERPRINT_OK) delay(50);

  if (finger.image2Tz(2) != FINGERPRINT_OK) {
    Serial.println("{\"event\":\"enroll_status\",\"step\":\"error\",\"msg\":\"Second image conversion failed\"}");
    showFailure();
    return;
  }

  if (finger.createModel() != FINGERPRINT_OK) {
    Serial.println("{\"event\":\"enroll_status\",\"step\":\"error\",\"msg\":\"Fingerprints did not match\"}");
    showFailure();
    return;
  }

  if (finger.storeModel(id) == FINGERPRINT_OK) {
    saveName(id, name);
    showSuccess();
    Serial.print("{\"event\":\"enroll_status\",\"step\":\"success\",\"id\":");
    Serial.print(id);
    Serial.print(",\"name\":\"");
    Serial.print(name);
    Serial.println("\",\"msg\":\"Enrollment successful!\"}");
  } else {
    showFailure();
    Serial.println("{\"event\":\"enroll_status\",\"step\":\"error\",\"msg\":\"Failed to store model in flash\"}");
  }

  while (finger.getImage() != FINGERPRINT_NOFINGER) delay(50);
}

// =====================
// AES-128 Encryption Helper
// =====================
String encryptAES128Hex(const String& plaintext) {
  mbedtls_aes_context aes;
  mbedtls_aes_init(&aes);
  mbedtls_aes_setkey_enc(&aes, AES_KEY, 128);

  size_t len = plaintext.length();
  size_t paddedLen = ((len / 16) + 1) * 16;
  uint8_t inputBlock[paddedLen];
  uint8_t outputBlock[paddedLen];

  memcpy(inputBlock, plaintext.c_str(), len);
  uint8_t padVal = paddedLen - len;
  for (size_t i = len; i < paddedLen; i++) {
    inputBlock[i] = padVal;
  }

  uint8_t ivCopy[16];
  memcpy(ivCopy, AES_IV, 16);

  mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, paddedLen, ivCopy, inputBlock, outputBlock);
  mbedtls_aes_free(&aes);

  String hexStr = "";
  for (size_t i = 0; i < paddedLen; i++) {
    if (outputBlock[i] < 16) hexStr += "0";
    hexStr += String(outputBlock[i], HEX);
  }

  return hexStr;
}

// =====================
// Send Encrypted Auth File via HTTP POST & UDP Broadcast to connected Hotspot devices
// =====================
void sendAuthFileToConnectedDevices(bool isSuccess, uint16_t id, const String& name) {
  String filename = isSuccess ? "auth_success.enc" : "auth_false.enc";

  String payload = "{";
  payload += "\"authenticated\":" + String(isSuccess ? "true" : "false") + ",";
  payload += "\"timestamp\":" + String(millis()) + ",";
  if (isSuccess) {
    payload += "\"user_id\":" + String(id) + ",";
    payload += "\"user_name\":\"" + name + "\"";
  } else {
    payload += "\"status\":\"AUTHENTICATION_FAILED\"";
  }
  payload += "}";

  String encryptedHex = encryptAES128Hex(payload);

  latestAuthFilename = filename;
  latestAuthHex = encryptedHex;

  // 1. Send UDP Hotspot Broadcast to 192.168.4.255 on ports 5000 and 2222
  IPAddress broadcastIP(192, 168, 4, 255);
  
  udpSender.beginPacket(broadcastIP, 5000);
  udpSender.print("SCP_TRANSFER ");
  udpSender.print(filename);
  udpSender.print(" ");
  udpSender.println(encryptedHex);
  udpSender.endPacket();

  udpSender.beginPacket(broadcastIP, 2222);
  udpSender.print("SCP_TRANSFER ");
  udpSender.print(filename);
  udpSender.print(" ");
  udpSender.println(encryptedHex);
  udpSender.endPacket();

  // 2. Query active stations connected to SoftAP to eliminate useless timeouts
  wifi_sta_list_t stationList;
  esp_wifi_ap_get_sta_list(&stationList);

  tcpip_adapter_sta_list_t adapterList;
  tcpip_adapter_get_sta_list(&stationList, &adapterList);

  if (adapterList.num > 0) {
    for (int i = 0; i < adapterList.num; i++) {
      IPAddress targetIP(adapterList.sta[i].ip.addr);
      sendHTTPPostAuthFile(targetIP, 5000, filename, encryptedHex);
      sendHTTPPostAuthFile(targetIP, 2222, filename, encryptedHex);
    }
  } else {
    // If station IP list is not populated yet, attempt default station IP 192.168.4.2 ONCE
    IPAddress targetIP(192, 168, 4, 2);
    sendHTTPPostAuthFile(targetIP, 5000, filename, encryptedHex);
    sendHTTPPostAuthFile(targetIP, 2222, filename, encryptedHex);
  }
}

bool sendHTTPPostAuthFile(const IPAddress& targetIP, uint16_t port, const String& filename, const String& contentHex) {
  WiFiClient client;
  client.setTimeout(1);

  // Fast 300ms non-blocking connection attempt
  if (client.connect(targetIP, port, 300)) {
    String jsonBody = "{\"filename\":\"" + filename + "\",\"data\":\"" + contentHex + "\"}";

    client.print("POST /upload_auth HTTP/1.1\r\n");
    client.print("Host: ");
    client.print(targetIP);
    client.print(":");
    client.print(port);
    client.print("\r\n");
    client.print("Content-Type: application/json\r\n");
    client.print("Content-Length: ");
    client.print(jsonBody.length());
    client.print("\r\n");
    client.print("Connection: close\r\n\r\n");
    client.print(jsonBody);
    client.flush();
    client.stop();

    Serial.print("{\"event\":\"http_post_sent\",\"target\":\"");
    Serial.print(targetIP);
    Serial.print(":\",\"port\":");
    Serial.print(port);
    Serial.print(",\"file\":\"");
    Serial.print(filename);
    Serial.println("\"}");
    return true;
  }
  return false;
}

// =====================
// NVS Storage Helper Functions
// =====================
void saveName(uint16_t id, const String& name) {
  prefs.putString(String(id).c_str(), name);
}

String loadName(uint16_t id) {
  return prefs.getString(String(id).c_str(), "");
}

void deleteName(uint16_t id) {
  prefs.remove(String(id).c_str());
}

// =====================
// LED Helper Functions
// =====================
void ledsOff() {
  digitalWrite(LED_RED_PIN, LOW);
  digitalWrite(LED_GREEN_PIN, LOW);
}

void showSuccess() {
  digitalWrite(LED_RED_PIN, LOW);
  digitalWrite(LED_GREEN_PIN, HIGH);
}

void showFailure() {
  digitalWrite(LED_GREEN_PIN, LOW);
  for (uint8_t i = 0; i < 5; i++) {
    digitalWrite(LED_RED_PIN, HIGH);
    delay(100);
    digitalWrite(LED_RED_PIN, LOW);
    delay(100);
  }
}

