/*
  ESP32 Wi-Fi Sniffer -> USB Serial -> Python Bridge -> Browser Dashboard
  -----------------------------------------------------------------------
  The ESP32 listens in promiscuous mode on all Wi-Fi channels (hopping)
  and forwards every received raw 802.11 frame over USB serial
  (NO Wi-Fi connection required!) to the host PC.

  Frame format – two frame types, distinguished by the 2nd sync byte:

  1) Packet frame (raw 802.11 data + metadata):
     [0xAA][0x55][len_lo][len_hi][channel(1B)][rssi(1B,signed)][payload...]
     - len  = total length AFTER the length field: 2 (meta) + payload length
     - channel: Wi-Fi channel on which the frame was received
     - rssi: signal strength in dBm (typically -30 to -90)

  2) Stats frame (sent every STATS_INTERVAL_MS):
     [0xAA][0x66][len_lo][len_hi][total(4B)][dropped(4B)][loops(4B)][heap(4B)]

  On the PC, serial_dashboard.py parses the frames and displays them
  live in the browser dashboard (no Wireshark required). Optionally it
  can also forward the raw frames via UDP to Wireshark/udpdump.

  IMPORTANT:
  - Baud rate: 921600 (for better throughput). The serial monitor and
    the Python script must use the same baud rate.
  - While the sniffer is running, NO readable text is sent over the
    serial link (binary data only). Debug text is printed only BEFORE
    the sniffer starts.
  - Use only on your own network or with explicit permission!
*/

#include <WiFi.h>
#include <esp_wifi.h>

const uint32_t SERIAL_BAUD = 921600;

const uint8_t CHANNEL_MIN = 1;
const uint8_t CHANNEL_MAX = 13;           // channels 1-13 used in most countries
const uint32_t HOP_INTERVAL_MS = 300;     // channel dwell time in ms
const uint32_t STATS_INTERVAL_MS = 5000;  // how often a stats frame is sent

volatile uint8_t currentChannel = CHANNEL_MIN;
uint32_t lastHop = 0;
uint32_t lastStats = 0;

#define SRCADDR_OFFSET 10

#define MAX_FRAME_LEN 800

typedef struct {
  uint16_t len;
  uint8_t channel;
  int8_t rssi;
  uint8_t data[MAX_FRAME_LEN];
} queued_packet_t;

static QueueHandle_t packetQueue = nullptr;

#define QUEUE_LENGTH 128

// Counters: volatile because written in Wi-Fi driver ISR context AND read
// from loop().
volatile uint32_t totalPackets = 0;
volatile uint32_t droppedPackets = 0;
volatile uint32_t loopIterations = 0;  // loop() calls per stats interval

// Runs in Wi-Fi driver context – copy only, NO Serial/heap calls here!
void IRAM_ATTR snifferCallback(void *buf, wifi_promiscuous_pkt_type_t type) {
  wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
  int len = pkt->rx_ctrl.sig_len;

  // Strip the 4-byte FCS appended by the ESP32 – Wireshark's wlan dissector
  // expects frames without FCS by default.
  len -= 4;

  if (len <= 0 || len > MAX_FRAME_LEN) return;
  if (packetQueue == nullptr) return;

  static const uint8_t BLUE_DS_MAC[6] = {0xa4, 0xc0, 0xe1, 0x5a, 0xfa, 0xe6};
  static const uint8_t PINK_DS_MAC[6] = {0x00, 0x1c, 0xbe, 0x51, 0x88, 0x1f};
  static const uint8_t WHITE_DS_MAC[6] = {0x2c, 0x10, 0xc1, 0x83, 0xa4, 0x30};
  int valid_mac = 0;
  if (memcmp(pkt->payload + SRCADDR_OFFSET, BLUE_DS_MAC, 6) == 0) valid_mac = 1;
  if (memcmp(pkt->payload + SRCADDR_OFFSET, PINK_DS_MAC, 6) == 0) valid_mac = 1;
  if (memcmp(pkt->payload + SRCADDR_OFFSET, WHITE_DS_MAC, 6) == 0) valid_mac = 1;
  if (!valid_mac) return;
  // if (len < 200) return;

  // static: keeps the struct off the small Wi-Fi task stack
  static queued_packet_t qp;
  qp.channel = currentChannel;
  qp.rssi = pkt->rx_ctrl.rssi;
  memcpy(qp.data, pkt->payload, len);
  qp.len = len;

  BaseType_t higherPriorityTaskWoken = pdFALSE;
  if (xQueueSendFromISR(packetQueue, &qp, &higherPriorityTaskWoken) == pdTRUE) {
    totalPackets++;
  } else {
    droppedPackets++;  // queue full – packet discarded
  }
}

void setup() {
  Serial.begin(SERIAL_BAUD);
  delay(500);

  // No WiFi.begin() / connect needed! The ESP32 runs purely in passive
  // promiscuous mode without joining any network. WIFI_STA still needs
  // to be set so the Wi-Fi driver initialises – we just never connect.
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  delay(100);

  packetQueue = xQueueCreate(QUEUE_LENGTH, sizeof(queued_packet_t));
  if (packetQueue == nullptr) {
    Serial.println("ERROR: Failed to create packet queue!");
    while (true) delay(1000);
  }

  Serial.print("Free heap after queue creation: ");
  Serial.print(ESP.getFreeHeap());
  Serial.println(" bytes");
  delay(100);  // ensure this line is flushed before binary data starts

  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&snifferCallback);
  esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);

  Serial.println("Sniffer started - channel hopping active (USB mode).");
  delay(200);  // ensure the text line is flushed before binary data follows
}

void loop() {
  loopIterations++;

  // Channel hopping
  /*if (millis() - lastHop > HOP_INTERVAL_MS) {
    currentChannel++;
    if (currentChannel > CHANNEL_MAX) currentChannel = CHANNEL_MIN;
    esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
    lastHop = millis();
  }*/
  currentChannel = 1;

  // Drain the queue and send each packet over serial (with framing header)
  queued_packet_t qp;
  while (xQueueReceive(packetQueue, &qp, 0) == pdTRUE) {
    uint16_t totalLen = 2 + qp.len;  // 2 meta bytes (channel + rssi) + payload
    uint8_t header[4];
    header[0] = 0xAA;
    header[1] = 0x55;
    header[2] = totalLen & 0xFF;
    header[3] = (totalLen >> 8) & 0xFF;
    Serial.write(header, 4);
    Serial.write(qp.channel);
    Serial.write((uint8_t)qp.rssi);
    Serial.write(qp.data, qp.len);
  }

  // Periodically send a stats frame (total + dropped + loop iterations + free heap)
  if (millis() - lastStats > STATS_INTERVAL_MS) {
    uint32_t total = totalPackets;
    uint32_t dropped = droppedPackets;
    uint32_t loops = loopIterations;
    uint32_t freeHeap = ESP.getFreeHeap();
    loopIterations = 0;  // reset per interval → gives rate, not cumulative sum

    uint8_t statsFrame[20];
    statsFrame[0] = 0xAA;
    statsFrame[1] = 0x66;  // 2nd sync byte distinguishes stats from packet frames
    statsFrame[2] = 16;    // payload length: 16 bytes (4x  04	81	09	[Last packet]	[Best packet]	00	00	00uint32, little-endian)
    statsFrame[3] = 0;
    memcpy(&statsFrame[4], &total, 4);
    memcpy(&statsFrame[8], &dropped, 4);
    memcpy(&statsFrame[12], &loops, 4);
    memcpy(&statsFrame[16], &freeHeap, 4);
    Serial.write(statsFrame, 20);

    lastStats = millis();
  }
}

