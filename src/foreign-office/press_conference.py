PRINT_CHAR = "█"
PALLET = [
    "\033[38;5;15m", #0 WHITE (BLANK)
    "\033[38;5;0m", #1 BLACK
    "" #2 N/A - SHOULDN'T HAPPEN
    "\033[38;5;213m", #3 LIGHT PINK
    "\033[38;5;201m", #4 BRIGHT PINK
    "\033[38;5;9m", #5 RED
    "\033[38;5;196m", #6 ORANGEY-RED
    "\033[38;5;202m", #7 ORANGE
    "\033[38;5;11m", #8 YELLOW
    "\033[38;5;10m", #9 LIGHT GREEN
    "\033[38;5;34m", #A GREEN
    "\033[38;5;14m", #B TURQUOISE
    "\033[38;5;45m", #C LIGHT BLUE
    "\033[38;5;39m", #D PALE BLUE
    "\033[38;5;21m", #E SLIGHTLY NOT ROYAL BLUE
    "\033[38;5;12m", #F FULL BLUE
]

TILE_WIDTH = 8
TILE_HEIGHT = 8

def decode_tiled_pixel(
    bitmap: bytes,
    x: int,
    y: int,
    backing_width: int,
) -> int:
    """
    Decode one pixel from row-major 8x8 tiled 4bpp storage.

    Tile order:

        tile row 0: tile 0, tile 1, tile 2, ...
        tile row 1: tile N, tile N+1, ...

    Within each tile row, the low nibble is the left pixel and the high
    nibble is the right pixel.
    """
    if x < 0 or y < 0 or x >= backing_width:
        return 0

    tiles_across = backing_width // TILE_WIDTH
    tile_x = x // TILE_WIDTH
    tile_y = y // TILE_HEIGHT

    within_tile_x = x % TILE_WIDTH
    within_tile_y = y % TILE_HEIGHT

    tile_index = tile_y * tiles_across + tile_x
    tile_bytes = TILE_WIDTH * TILE_HEIGHT // 2

    tile_offset = tile_index * tile_bytes
    row_offset = within_tile_y * (TILE_WIDTH // 2)
    byte_offset = tile_offset + row_offset + within_tile_x // 2

    if byte_offset >= len(bitmap):
        return 0

    value = bitmap[byte_offset]

    # Protocol notes: low nibble is left pixel, high nibble is right pixel.
    if within_tile_x % 2 == 0:
        return value & 0x0F

    return value >> 4

def print_canvas(
    bitmap: bytes,
    backing_width: int,
    visible_width: int,
    height: int,
    x_offset: int,
) -> None:
    """
    Print a compact ASCII rendering.

    Two source rows are combined into one terminal row because terminal
    characters are taller than they are wide.
    """
    if backing_width % 8 != 0:
        raise ValueError("backing width must be divisible by 8")

    if x_offset < 0:
        raise ValueError("x_offset cannot be negative")

    if x_offset + visible_width > backing_width:
        raise ValueError(
            f"x_offset + visible_width exceeds backing width: "
            f"{x_offset} + {visible_width} > {backing_width}"
        )

    print("    Canvas preview:")

    for y in range(0, height, 2):
        line = "    |"

        for output_x in range(visible_width):
            source_x = x_offset + output_x

            first = decode_tiled_pixel(
                bitmap,
                source_x,
                y,
                backing_width,
            )

            if y + 1 < height:
                second = decode_tiled_pixel(
                    bitmap,
                    source_x,
                    y + 1,
                    backing_width,
                )
                value = max(first, second)
            else:
                value = first

            line += PALLET[min(value, len(PALLET) - 1)]
            line += PRINT_CHAR

            # line += ASCII_PALETTE[min(value, len(ASCII_PALETTE) - 1)]

        line += "|"

        if line.strip("|").strip():
            print(line)

    print("\033[0m")