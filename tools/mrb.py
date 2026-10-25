import struct, io
from PIL import Image

def cushort(b, p):
    if b[p] & 1:
        return (struct.unpack_from('<H', b, p)[0] >> 1), p + 2
    return b[p] >> 1, p + 1

def culong(b, p):
    if b[p] & 1:
        return (struct.unpack_from('<I', b, p)[0] >> 1), p + 4
    return (struct.unpack_from('<H', b, p)[0] >> 1), p + 2

def lz77(data):
    out = bytearray(); p = 0
    while p < len(data):
        flags = data[p]; p += 1
        for bit in range(8):
            if p >= len(data): break
            if flags & (1 << bit):
                v = data[p] | (data[p+1] << 8); p += 2
                ln = (v >> 12) + 3; off = (v & 0xFFF) + 1
                for _ in range(ln):
                    out.append(out[-off])
            else:
                out.append(data[p]); p += 1
    return bytes(out)

def rle(data):
    out = bytearray(); p = 0
    while p < len(data):
        b = data[p]; p += 1
        if b & 0x80:
            n = b & 0x7F
            out += data[p:p+n]; p += n
        else:
            out += bytes([data[p]]) * b; p += 1
    return bytes(out)

def decode(bm, index=0):
    magic, n = struct.unpack_from('<HH', bm, 0)
    assert magic in (0x506C, 0x706C), hex(magic)
    off = struct.unpack_from('<I', bm, 4 + 4*index)[0]
    t, pack = bm[off], bm[off+1]
    assert t in (5, 6), t
    p = off + 2
    xd, p = culong(bm, p); yd, p = culong(bm, p)
    planes, p = cushort(bm, p); bits, p = cushort(bm, p)
    w, p = culong(bm, p); h, p = culong(bm, p)
    used, p = culong(bm, p); imp, p = culong(bm, p)
    csize, p = culong(bm, p); hsize, p = culong(bm, p)
    coff, hoff = struct.unpack_from('<II', bm, p); p += 8
    ncol = used if used else (1 << bits if bits <= 8 else 0)
    pal = bm[p:p + 4*ncol]
    raw = bm[off+coff: off+coff+csize]
    if pack in (2, 3): raw = lz77(raw)
    if pack in (1, 3): raw = rle(raw)
    stride = ((w * bits * planes + 31) // 32) * 4
    raw = raw[:stride*h].ljust(stride*h, b'\0')
    hdr = struct.pack('<2sIHHI', b'BM', 14+40+len(pal)+len(raw), 0, 0, 14+40+len(pal))
    dib = struct.pack('<IiiHHIIiiII', 40, w, h, planes, bits, 0, len(raw), 0, 0, ncol, 0)
    img = Image.open(io.BytesIO(hdr + dib + pal + raw)); img.load()
    return img.convert('RGB'), dict(w=w, h=h, bits=bits, pack=pack, n=n)
