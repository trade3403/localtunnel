"""Generate deterministic original LocalTunnel icons without third-party packages."""
from pathlib import Path
import struct
import zlib

icons = Path(__file__).resolve().parents[1] / "src-tauri" / "icons"
icons.mkdir(exist_ok=True)

def png(size):
    raw = bytearray()
    for y in range(size):
        raw.append(0)
        for x in range(size):
            a, b = x * 32 // size, y * 32 // size
            # Two white linked rectangles on a blue background.
            white = (6 <= a <= 15 and 9 <= b <= 22 and (a in (6, 7, 14, 15) or b in (9, 10, 21, 22))) or (16 <= a <= 25 and 9 <= b <= 22 and (a in (16, 17, 24, 25) or b in (9, 10, 21, 22))) or (12 <= a <= 19 and 15 <= b <= 16)
            raw.extend((255, 255, 255, 255) if white else (35, 103, 229, 255))
    def chunk(tag, data):
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xffffffff)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)) + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b"")

images = [(32, png(32)), (48, png(48)), (256, png(256))]
offset = 6 + len(images) * 16
entries, payload = bytearray(), bytearray()
for size, image in images:
    entries.extend(struct.pack("<BBBBHHII", size % 256, size % 256, 0, 0, 1, 32, len(image), offset))
    payload.extend(image)
    offset += len(image)
(icons / "icon.ico").write_bytes(struct.pack("<HHH", 0, 1, len(images)) + entries + payload)
(icons / "icon.png").write_bytes(images[-1][1])
