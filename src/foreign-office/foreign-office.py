import serial
import sys
import queue
import threading
import struct
import time
import binascii
from typing import Optional
from dataclasses import dataclass

SYNC_BYTE_1        = 0xAA
SYNC_BYTE_2_PACKET = 0x55
SYNC_BYTE_2_STATS = 0x66
SYNC_SEQ_PACKET = bytes([SYNC_BYTE_1, SYNC_BYTE_2_PACKET])
SYNC_SEQ_STATS = bytes([SYNC_BYTE_1, SYNC_BYTE_2_STATS])

TYPE_NAMES = {0: "Management", 1: "Control", 2: "Data", 3: "Extension"}
SUBTYPE_NAMES = {
    (0, 0): "Assoc Request", (0, 1): "Assoc Response",
    (0, 4): "Probe Request", (0, 5): "Probe Response",
    (0, 8): "Beacon", (0, 10): "Disassociation",
    (0, 11): "Authentication", (0, 12): "Deauthentication",
    (1, 11): "RTS", (1, 12): "CTS", (1, 13): "ACK",
    (2, 0): "Data", (2, 4): "Null (no data)",
    (2, 8): "QoS Data", (2, 12): "QoS Null",
}

@dataclass
class Client:
    mac: str

@dataclass
class Message:
    source: Client
    destination: Client
    frame_len: int
    # header_len: int
    # data_len: int
    # full_frame: bytearray
    # data: bytearray
    # counter: 
    # end: bytearray

    def __str__(self):
        #return f"{binascii.hexlify(self.full_frame)}\nMessage: FROM {self.source.mac} TO {self.destination.mac} WITH HEADER LENGTH {self.header_len} AND DATA LENGTH {self.data_len}\n{binascii.hexlify(self.data)}\n\n"
        #return f"{self.counter}"
        return ""

raw_byte_queue = queue.Queue()
message_queue = queue.Queue()

def raw_serial_reader(port: str, baud: int):
    try:
        ser = serial.Serial(port, baud, timeout=1)
    except serial.SerialException as e:
        print(f"ERROR opening serial port: {e}", file=sys.stderr)
        sys.exit(1)

    while True:
        chunk = ser.read(4096)
        if not chunk:
            continue
        raw_byte_queue.put_nowait(chunk)

def frame_parser():
    byte_buffer = bytearray()

    while True:
        chunk = raw_byte_queue.get()
        byte_buffer.extend(chunk)

        while True:
            idx_packet = byte_buffer.find(SYNC_SEQ_PACKET)
            idx_stats = byte_buffer.find(SYNC_SEQ_STATS)
            candidates = [i for i in (idx_packet, idx_stats) if i != -1]
            sync_index = min(candidates) if candidates else -1

            if sync_index == -1:
                if len(byte_buffer) > 1:
                    del byte_buffer[:-1]
                break

            if sync_index > 0:
                del byte_buffer[:sync_index]

            if len(byte_buffer) < 4:
                break

            length = byte_buffer[2] | (byte_buffer[3] << 8)
            if len(byte_buffer) < 4 + length:
                break

            payload = bytes(byte_buffer[4:4 + length])
            frame_type = byte_buffer[1]
            del byte_buffer[:4 + length]

            if frame_type == SYNC_BYTE_2_PACKET:
                if len(payload) < 2:
                    continue
                channel = payload[0]
                rssi = struct.unpack("b", payload[1:2])[0]
                frame_80211 = payload[2:]

                parsed = parse_80211(frame_80211, channel, rssi)
                if parsed is None:
                    continue
                message_queue.put_nowait(parsed)
                # if parsed.data_len != 114:
                #     continue
                print(parsed)

def parse_80211(frame: bytes, channel: int, rssi: int):
    if len(frame) < 24:
        return None

    fc0 = frame[0]
    version = fc0 & 0x03
    ftype = (fc0 >> 2) & 0x03
    subtype = (fc0 >> 4) & 0x0F

    addr1 = frame[4:10].hex(":")
    addr2 = frame[10:16].hex(":") if len(frame) >= 16 else None
    addr3 = frame[16:22].hex(":") if len(frame) >= 22 else None

    ssid = None
    if ftype == 0 and subtype == 8 and len(frame) > 36: # Beacon frame
        ssid = parse_ssid_from_tags(frame, 36)
    elif ftype == 0 and subtype == 5 and len(frame) > 36: # Probe response
        ssid = parse_ssid_from_tags(frame, 36)
    elif ftype == 0 and subtype == 4 and len(frame) > 24: # Probe request
        ssid = parse_ssid_from_tags(frame, 24)

    ftype_name = TYPE_NAMES.get(ftype, f"type{ftype}")
    subtype_name = SUBTYPE_NAMES.get((ftype, subtype), f"subtype{subtype}")

    header_len = header_length(frame)
    frame_len = len(frame)

    print(binascii.hexlify(frame), "-", frame_len)

    message = Message(
        source=Client(addr2),
        destination=Client(addr1),
        frame_len=frame_len
    )

    # 
    # end = frame[-4:] if len(frame) > 4 else None
    # message = Message(Client(addr2), Client(addr1), header_len, data_len, frame, frame[header_len:], end)

    return message

def header_length(frame: bytes):
    fc0, fc1 = frame[0], frame[1]
    ftype = (fc0 >> 2) & 0x03
    subtype = (fc0 >> 4) & 0x0F
    to_ds = fc1 & 0x01
    from_ds = (fc1 >> 1) & 0x01
    order = fc1 & 0x80

    if ftype == 1:  # Control
        return {11: 16, 12: 10, 13: 10}.get(subtype, 16)  # RTS 16, CTS/ACK 10

    hdr = 24
    if ftype == 2 and to_ds and from_ds:
        hdr += 6
    if ftype == 2 and (subtype & 0x08):  # QoS
        hdr += 2
        if order:
            hdr += 4
    elif ftype == 0 and order:
        hdr += 4
    return hdr

def parse_ssid_from_tags(frame: bytes, tag_start: int) -> Optional[str]:
    offset = tag_start
    while offset + 2 <= len(frame):
        tag_num  = frame[offset]
        tag_len = frame[offset + 1]
        value_start = offset + 2
        value_end = value_start + tag_len
        if value_end > len(frame):
            break
        if tag_num == 0: # Found SSID
            raw = frame[value_start:value_end]
            if tag_len == 0:
                return "<hidden/broadcast>"
            try:
                return raw.decode("utf-8", errors="replace")
            except Exception:
                return raw.hex()
        offset = value_end
    return None

def main():
    threads = []
    for target, kwargs in [
        (raw_serial_reader, {"port": "/dev/ttyUSB0", "baud": 921600}),
        (frame_parser,      {}),
    ]:
        t = threading.Thread(target=target, kwargs=kwargs, daemon=True)
        t.start()
        threads.append(t)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()
