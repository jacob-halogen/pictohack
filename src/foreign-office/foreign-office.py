import serial
import sys
import queue
import threading
import struct
import time
import binascii
from typing import Optional
from dataclasses import dataclass
from press_conference import *

SYNC_BYTE_1        = 0xAA
SYNC_BYTE_2_PACKET = 0x55
SYNC_BYTE_2_STATS = 0x66
SYNC_SEQ_PACKET = bytes([SYNC_BYTE_1, SYNC_BYTE_2_PACKET])
SYNC_SEQ_STATS = bytes([SYNC_BYTE_1, SYNC_BYTE_2_STATS])

@dataclass
class Client:
    mac: str

@dataclass
class Message:
    source: Client
    destination: Client
    payloads: dict[int, bytes]
    last_idx: Optional[int] = None

    def is_complete(self):
        return self.last_idx is not None and len(self.payloads) == self.last_idx + 1

    def get_output(self):
        return [{"byte_counter": b, "payload": p} for b, p in self.payloads.items()]

    def __str__(self):
        return "".join(self.payloads[o].hex() for o in sorted(self.payloads))

raw_byte_queue = queue.Queue()
messages: dict[tuple, Message] = {}
done_queue = queue.Queue()

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

                parse_80211(frame_80211, channel, rssi)

def parse_80211(frame: bytes, channel: int, rssi: int):
    if len(frame) < 46:
        return

    dest = frame[4:10].hex(":")
    src = frame[10:16].hex(":")
    if dest != "03:09:bf:00:00:00":
        return
    
    offset = int.from_bytes(frame[38:42], 'little')
    counter = int.from_bytes(frame[-4:-2], 'little')
    idx = offset // 160
    key = (src, (counter - idx) & 0xFFFF)
    payload = bytes(frame[42:-4])

    msg = messages.get(key)
    if msg is None:
        msg = messages[key] = Message(Client(src), Client(dest), {})

    msg.payloads[offset] = payload
    if frame[32] != 0xAC:
        msg.last_idx = idx

    if msg.is_complete():
        del messages[key]
        done_queue.put(msg)

def message_outputter():
    while True:
        done = done_queue.get()
        print(done.payloads)
        display_message(done.get_output()).show()

def main():
    threads = []
    for target, kwargs in [
        (raw_serial_reader, {"port": "/dev/ttyACM0", "baud": 921600}),
        (frame_parser,      {}),
        (message_outputter, {}),
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
