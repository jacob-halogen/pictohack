import queue
import serial
import struct
import sys
import threading
from dataclasses import dataclass, field
from typing import Optional

from scapy.layers.dot11 import Dot11
from scapy.packet import Raw

from press_conference import print_canvas

## ESP32 FRAME INFORMATION

SYNC_BYTE = 0xAA
FRAME_PACKET = 0x55
FRAME_STATS = 0x66

SYNC_PACKET = bytes((SYNC_BYTE, FRAME_PACKET))
SYNC_STATS = bytes((SYNC_BYTE, FRAME_STATS))

SERIAL_PORT = "/dev/ttyACM0"
SERIAL_BAUD = 921600

## NINTENDO/PICTOCHAT ADDRESSES

DS_BSSID = "00:23:cc:f8:9e:3e"
CLIENT_MC = "03:09:bf:00:00:00"
ACK_MC = "03:09:bf:00:00:03"
CLT_MC = "03:09:bf:00:00:10"

## PICTOCHAT APPLICATION VALUES

DRAWING_MAGIC = 0x03
DRAWING_SUBTYPE = 0x02
DRAWING_HEADER_SIZE = 36

## FRAGMENT LAYOU

DATA_FRAGMENT_HEADER_SIZE = 8

FRAG_SENDER_ID_OFFSET = 0
FRAG_KIND_OFFSET = 1
FRAG_PAYLOAD_LENGTH_OFFSET = 2
FRAG_WRITE_OFFSET_OFFSET = 4
FRAG_MAGIC_OFFSET = 6
FRAG_PAYLOAD_OFFSET = 8

FRAG_FINAL_FLAG = 0x01

FRAG_TYPE_FIRST = 0xFF
FRAG_TYPE_MIDDLE = 0x97
FRAG_TYPE_FINAL = 0x04

KNOWN_FRAGMENT_TYPES = {
    FRAG_TYPE_FIRST,
    FRAG_TYPE_MIDDLE,
    FRAG_TYPE_FINAL,
}

## DRAWING

BACKING_WIDTH = 256
VISIBLE_WIDTH = 228
BITS_PER_PIXEL = 4
BYTES_PER_PIXEL_PAIR = 1
BYTES_PER_ROW = BACKING_WIDTH // 2
BYTES_PER_16_PIXEL_BAND = BYTES_PER_ROW * 16

PICTOCHAT_X_OFFSET = 24

## DATA

raw_byte_queue: queue.Queue[bytes] = queue.Queue()

seen_frames = 0

@dataclass
class Fragment:
    offset: int
    payload: bytes

@dataclass
class Transfer: # stores information about current transmission
    source_mac: str
    total_size: int
    data: bytearray
    received: bytearray
    offsets: set[int] = field(default_factory=set)
    fragments: dict[int, Fragment] = field(default_factory=dict)

    def add_fragment(self, fragment: Fragment) -> None:
        start = fragment.offset
        end = start + len(fragment.payload)

        if start < 0 or start >= self.total_size: # reject fragments outside of expected transfer range
            raise ValueError(
                f"offset {start} outside transfer of {self.total_size} bytes"
            )

        end = min(end, self.total_size)
        copy_len = end - start

        if copy_len <= 0:
            return

        payload = fragment.payload[:copy_len]

        for index, incoming in enumerate(payload, start):
            if self.received[index] and self.data[index] != incoming: # throw error if re-transmitted fragment has differing data - means corruption somewhere
                raise ValueError(
                    f"conflicting overlap at byte {index}: "
                    f"existing=0x{self.data[index]:02x}, "
                    f"incoming=0x{incoming:02x}"
                )

        self.data[start:end] = payload
        self.received[start:end] = b"\x01" * copy_len
        self.offsets.add(start)
        self.fragments[start] = fragment

    def missing_bytes(self) -> int:
        return self.received.count(0)

    def is_complete(self) -> bool:
        return self.missing_bytes() == 0


active_transfers: dict[str, Transfer] = {}

## UTILS

def unswap_mac(raw6: bytes) -> str: # fix Nintendo's stupid flipped mac adress nonsense
    if len(raw6) != 6:
        raise ValueError(f"expected six MAC bytes, got {len(raw6)}")

    return ":".join(f"{raw6[i ^ 1]:02x}" for i in range(6))


def hexd(data: bytes, indent: str = "    ") -> str: # converts a collection of bytes into hex string
    lines: list[str] = []

    for offset in range(0, min(len(data), 64), 16):
        chunk = data[offset:offset + 16]
        hex_part = " ".join(f"{byte:02x}" for byte in chunk)
        ascii_part = "".join(
            chr(byte) if 32 <= byte < 127 else "."
            for byte in chunk
        )
        lines.append(
            f"{indent}{offset:04x}  "
            f"{hex_part:<47}  {ascii_part}"
        )

    if len(data) > 64:
        lines.append(f"{indent}... ({len(data)} bytes total)")

    return "\n".join(lines)


def read_u16_le(data: bytes, offset: int) -> int: # gets data from bytes at a specific position
    if offset + 2 > len(data):
        raise ValueError(
            f"cannot read u16 at offset {offset} from {len(data)} bytes"
        )
    return struct.unpack_from("<H", data, offset)[0]


def normalise_mac(value: Optional[str]) -> str: # make the mac address look nice
    return (value or "").lower()


## ESP FRAME HANDLING

def raw_serial_reader(port: str, baud: int) -> None: # read data from serial in chunks and add to queue for processing
    try:
        serial_port = serial.Serial(port, baud, timeout=1)
    except serial.SerialException as exc:
        print(f"ERROR opening serial port: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc

    while True:
        chunk = serial_port.read(4096)
        if chunk:
            raw_byte_queue.put(chunk)


def frame_parser() -> None: # read from raw bytes and group into frames using ESP sync packet markers
    byte_buffer = bytearray()

    while True:
        byte_buffer.extend(raw_byte_queue.get())

        while True:
            packet_index = byte_buffer.find(SYNC_PACKET)
            stats_index = byte_buffer.find(SYNC_STATS)

            candidates = [
                index
                for index in (packet_index, stats_index)
                if index >= 0
            ]

            sync_index = min(candidates) if candidates else -1

            if sync_index < 0:
                # Preserve a possible leading 0xAA for a split sync sequence.
                if len(byte_buffer) > 1:
                    del byte_buffer[:-1]
                break

            if sync_index:
                del byte_buffer[:sync_index]

            if len(byte_buffer) < 4:
                break

            frame_type = byte_buffer[1]
            payload_length = byte_buffer[2] | (byte_buffer[3] << 8)
            complete_length = 4 + payload_length

            if len(byte_buffer) < complete_length:
                break

            payload = bytes(byte_buffer[4:complete_length])
            del byte_buffer[:complete_length]

            if frame_type == FRAME_PACKET:
                process_packet_payload(payload)


def process_packet_payload(payload: bytes) -> None: # convert raw bytes into scapy Dot11 class for easier manipulation and storage
    if len(payload) < 3:
        print("[ESP packet] payload too short")
        return

    ieee_frame = payload[2:]

    try:
        packet = Dot11(ieee_frame)
    except Exception as exc:
        print(f"[802.11] decode failed: {exc}")
        return

    handle_packet(packet)

## PICTOCHAT PACKET CLASSIFICAION

def handle_packet(packet: Dot11) -> None: # check that the packet has a valid nintendo destination and source and handle based on client or host sender
    global seen_frames

    if not packet.haslayer(Dot11):
        return

    dot11 = packet[Dot11]

    if dot11.type != 2:
        return

    addresses = [
        dot11.addr1 or "",
        dot11.addr2 or "",
        dot11.addr3 or "",
    ]

    has_nintendo_oui = any(
        "03:09:bf" in address.lower()
        for address in addresses
    )
    has_known_bssid = any(
        DS_BSSID.lower() in address.lower()
        for address in addresses
    )

    if not (has_nintendo_oui or has_known_bssid): # reject packet if not from or to valid address
        return

    if not packet.haslayer(Raw): # if packet has no data ignore it as packet is just keep-alive esque
        return

    raw_payload = bytes(packet[Raw])
    source = dot11.addr2 or "?"
    destination = dot11.addr1 or "?"

    seen_frames += 1

    if normalise_mac(destination) in {
        CLIENT_MC.lower(),
        ACK_MC.lower(),
    }:
        handle_host_frame(
            payload=raw_payload,
            source=source,
        )
    else:
        handle_client_frame(
            payload=raw_payload,
            source=source,
        )

# host packet:
# byte 0 - contant value (useless)
# byte 1 - application size (used to figure out where the actual packet data is)
# byte 2 - packet flags (ignored)
# byte 3+ - actual packet data (what we need)
# trailing bytes - nintendo footer (ignored)
def handle_host_frame(
    payload: bytes,
    source: str,
) -> None:
    if len(payload) < 3:
        return

    application_size = payload[1] * 2

    if application_size == 0:
        return

    application = payload[3:3 + application_size]

    if len(application) < 4:
        return

    decode_picto(application, source)

# client packet:
# byte 0 - application size (used to figure our where the actual packet data is)
# byte 1 - flags (ignored)
# byte 2+ - actual packet data (what we need)
def handle_client_frame(
    payload: bytes,
    source: str,
) -> None:
    if len(payload) < 2:
        return

    application_size = payload[0]

    if application_size == 0:
        return

    application = payload[2:2 + application_size]

    if len(application) < 4:
        return

    decode_picto(application, source)

## MAIN PICTOCHAT DECODING

def decode_picto(application: bytes, source: str) -> None:
    if len(application) < 4:
        return

    type_id = read_u16_le(application, 0)
    record_size = read_u16_le(application, 2)

    if record_size < 4:
        return

    record_end = min(record_size, len(application)) 
    body = application[4:record_end] # get actual body removing footer from payload

    match type_id:
        case 1:
            decode_transfer_header(body, source)
        case 2:
            decode_data_fragment(body, source)
        case 4, 5:
            decode_roster(body)
        case 0, 3, 6: # ignore these messages
            return

def decode_transfer_header(body: bytes, source: str) -> None: # someone has triggered the start of a new message so create an entry for it
    if len(body) < 6:
        return

    total_size = read_u16_le(body, 4)

    if total_size in (0, 0xFFFF):
        return

    existing = active_transfers.get(source)

    if existing is not None:
        if existing.total_size == total_size: # dont update a transfer from the same source if the header size differs
            return

    active_transfers[source] = Transfer( # create entry for new transfer that has started
        source_mac=source,
        total_size=total_size,
        data=bytearray(total_size),
        received=bytearray(total_size),
    )

def decode_roster(body: bytes) -> None: # client or host has registered a change in the room members so print that change to the terminal
    if len(body) < 4:
        return

    members: list[str] = []

    for slot in range(16):
        offset = 4 + slot * 6

        if offset + 6 > len(body):
            break

        raw_mac = body[offset:offset + 6]

        if raw_mac == b"\x00" * 6:
            continue

        members.append(f"Slot {slot}: {unswap_mac(raw_mac)}")

    if members:
        print(f"Roster ping - Room members ({', '.join(members)})")

# pictochat data fragment:
# byte 0 - sender/console ID (ignored)
# byte 1 - fragment kind (ignored)
# byte 2/3 - payload length (how many bytes the fragment says it contains)
# byte 4/5 - write offset (the start point of the fragment within the whole packet)
# byte 6/7 - constant magic value (useless)
# byte 8+ - actual image data (what we want)
def decode_data_fragment(body: bytes, source: str) -> None:
    if len(body) < 8:
        return

    declared_length = read_u16_le(body, 2)
    write_offset = read_u16_le(body, 4)

    available_length = len(body) - 8
    actual_length = min(declared_length, available_length)

    payload = body[8:8 + actual_length]

    transfer = active_transfers.get(source)
    if transfer is None:
        return

    if write_offset >= transfer.total_size:
        return

    remaining = transfer.total_size - write_offset

    usable_length = min(len(payload), remaining)
    if usable_length <= 0:
        return
    
    fragment = Fragment(
        offset=write_offset,
        payload=payload[:usable_length],
    )
    
    try:
        transfer.add_fragment(fragment)
    except ValueError as exc:
        return

    if not transfer.is_complete(): # dont print an incomplete message
        return

    full_record = bytes(transfer.data)
    del active_transfers[source]

    bitmap = full_record[DRAWING_HEADER_SIZE:]
    if len(bitmap) % BYTES_PER_16_PIXEL_BAND != 0:
        return

    print(
        f"\n*** COMPLETE MESSAGE from {source} "
        f"({len(full_record)}B) ***"
    )

    decode_drawing_record(full_record)

## DRAWING DECODING

def decode_drawing_record(record: bytes) -> None:
    if len(record) < DRAWING_HEADER_SIZE:
        return

    author = unswap_mac(record[2:8])

    print(f"    Author: {author}")

    bitmap = record[DRAWING_HEADER_SIZE:]

    if not bitmap:
        print("    Drawing bitmap is empty")
        return

    if len(bitmap) % BYTES_PER_16_PIXEL_BAND != 0: # drawing is not right size so ignore it
        return

    height = len(bitmap) // BYTES_PER_ROW

    if height <= 0: # ignore drawings that dont have a full size
        return

    if height % 16 != 0:
        print(
            f"    WARNING: derived height {height} is not a multiple of 16"
        )

    print(
        f"    Backing bitmap: {BACKING_WIDTH}x{height}; "
        f"visible width: {VISIBLE_WIDTH}; "
        f"x offset: {PICTOCHAT_X_OFFSET}"
    )

    print_canvas(
        bitmap,
        backing_width=BACKING_WIDTH,
        visible_width=VISIBLE_WIDTH,
        height=height,
        x_offset=PICTOCHAT_X_OFFSET,
    )

## MAIN

def main() -> None:
    threads = [
        threading.Thread(
            target=raw_serial_reader,
            kwargs={
                "port": SERIAL_PORT,
                "baud": SERIAL_BAUD,
            },
            daemon=True,
        ),
        threading.Thread(
            target=frame_parser,
            daemon=True,
        ),
    ]

    for thread in threads:
        thread.start()

    print(
        f"Listening on {SERIAL_PORT} at {SERIAL_BAUD} baud"
    )
    print(
        f"PictoChat backing bitmap: {BACKING_WIDTH}px wide"
    )
    print(
        f"Visible bitmap: {VISIBLE_WIDTH}px wide "
        f"with x offset {PICTOCHAT_X_OFFSET}"
    )
    print("Press Ctrl+C to stop.")

    try:
        for thread in threads:
            thread.join()
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()