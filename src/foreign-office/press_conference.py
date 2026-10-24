from PIL import Image

PICTOCHAT_NORMAL_PAYLOAD = 160

sample_payload = bytes([0x0F, 0xF0] * (160 // 2))  # alternating nibble pattern, 160 bytes total

packets = [
    {'byte_counter': i, 'payload': sample_payload}
    for i in range(25)  # 25 unique -> blocks = 2, non-empty image
]

def decode_chunk(im, raw, at, chunkx, chunky, w):
    """
    Decodes one 8x8 tile of nibble-packed pixel data into the RGB buffer `im`.
    Mirrors the original C pointer arithmetic: each byte in `raw` holds two
    pixels (low nibble, high nibble); any nonzero nibble is painted black.
    Returns the updated `at` offset into `raw`.
    """
    for i in range(8 * 8 // 2):
        if chunkx * 8 + (i % 4) * 2 < w:
            idx = chunkx * 8 + (i % 4) * 2 + w * ((i // 4) + chunky * 8)

            if (raw[at] & 0xf) != 0:
                im[3 * idx + 0] = 0x00
                im[3 * idx + 1] = 0x00
                im[3 * idx + 2] = 0x00

            if (raw[at] >> 4) != 0:
                idx2 = idx + 1
                im[3 * idx2 + 0] = 0x00
                im[3 * idx2 + 1] = 0x00
                im[3 * idx2 + 2] = 0x00
        at += 1
    return at


def display_message(packets):
    """
    packets: list of dicts, each with:
        'byte_counter': int
        'payload':      bytes/bytearray of length PICTOCHAT_NORMAL_PAYLOAD (160)
    (i.e. one entry per captured pictochat_packet, in the order received)

    Returns a PIL Image on success, or None if there wasn't enough data
    to form a complete message (mirrors the original function returning 0).
    """
    packet_count = len(packets)
    if packet_count == 0:
        print("ARGAGAG NO PACKETS")
        return None

    # Count unique packets, deduping consecutive retransmissions by byte_counter
    j = 1
    print(packet_count)
    for i in range(1, packet_count):
        if packets[i]['byte_counter'] != packets[i - 1]['byte_counter']:
            j += 1

    blocks = (j - 1) // 12
    width = 220
    height = blocks * 16
    if blocks <= 0:
        print("ARGGHSGAHA NO BLOCKA")
        return None

    im = bytearray(b'\xff' * (width * height * 3))

    # Original C code allocates (j+1)*PAYLOAD bytes but then memsets a
    # further PAYLOAD bytes past that (an off-by-one in the source) -
    # allocate one extra chunk here so the trailing memset stays in bounds.
    raw = bytearray((j + 2) * PICTOCHAT_NORMAL_PAYLOAD)

    j = 0
    raw[0:PICTOCHAT_NORMAL_PAYLOAD] = packets[0]['payload']
    for i in range(1, packet_count):
        if packets[i]['byte_counter'] != packets[i - 1]['byte_counter']:
            j += 1
            start = j * PICTOCHAT_NORMAL_PAYLOAD
            raw[start:start + PICTOCHAT_NORMAL_PAYLOAD] = packets[i]['payload']

    # Trailing block already zeroed since bytearray() initializes to 0,
    # matching the original's memset(raw+(j+1)*PAYLOAD, 0, PAYLOAD)

    k = 166
    for j in range(blocks * 2):
        for i in range(224 // 8):
            k = decode_chunk(im, raw, k, i, j, width)
        k += 4 * 8 * 4

    return Image.frombytes('RGB', (width, height), bytes(im))

# print(packets)
# display_message(packets).show()
