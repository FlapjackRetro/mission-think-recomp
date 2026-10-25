#!/usr/bin/env python3
"""Minimal ISO9660 (+Joliet) lister/extractor. Usage: isoread.py list|extract ISO [OUTDIR]"""
import os, struct, sys

SEC = 2048

def rd(f, lba, n=1):
    f.seek(lba * SEC)
    return f.read(n * SEC)

def find_vds(f):
    prim = jol = None
    lba = 16
    while True:
        d = rd(f, lba)
        if d[1:6] != b'CD001':
            break
        t = d[0]
        if t == 1 and prim is None:
            prim = d
        elif t == 2 and d[88:91] in (b'%/@', b'%/C', b'%/E'):
            jol = d
        elif t == 255:
            break
        lba += 1
    return prim, jol

def parse_dir(f, lba, size, joliet):
    out = []
    data = b''.join(rd(f, lba + i) for i in range((size + SEC - 1) // SEC))
    pos = 0
    while pos < size:
        ln = data[pos]
        if ln == 0:
            pos = (pos // SEC + 1) * SEC
            continue
        rec = data[pos:pos + ln]
        pos += ln
        ext = struct.unpack('<I', rec[2:6])[0]
        sz = struct.unpack('<I', rec[10:14])[0]
        flags = rec[25]
        nl = rec[32]
        raw = rec[33:33 + nl]
        if raw in (b'\x00', b'\x01'):
            continue
        name = raw.decode('utf-16-be', 'replace') if joliet else raw.decode('latin-1')
        if not joliet or True:
            if ';' in name:
                name = name.rsplit(';', 1)[0]
            if name.endswith('.') and len(name) > 1:
                name = name[:-1]
        out.append((name, ext, sz, bool(flags & 2)))
    return out

def walk(f, lba, size, joliet, prefix=''):
    for name, ext, sz, isdir in parse_dir(f, lba, size, joliet):
        p = prefix + '/' + name
        if isdir:
            yield (p, ext, 0, True)
            yield from walk(f, ext, sz, joliet, p)
        else:
            yield (p, ext, sz, False)

def main():
    cmd, iso = sys.argv[1], sys.argv[2]
    f = open(iso, 'rb')
    prim, jol = find_vds(f)
    vd, joliet = (jol, True) if jol else (prim, False)
    root = vd[156:190]
    rlba = struct.unpack('<I', root[2:6])[0]
    rsz = struct.unpack('<I', root[10:14])[0]
    entries = list(walk(f, rlba, rsz, joliet))
    print(f"# joliet={joliet} entries={len(entries)}", file=sys.stderr)
    if cmd == 'list':
        for p, lba, sz, isdir in entries:
            print(f"{'D' if isdir else 'F'} {sz:>10} {p}")
    else:
        out = sys.argv[3]
        for p, lba, sz, isdir in entries:
            dst = os.path.join(out, p.lstrip('/'))
            if isdir:
                os.makedirs(dst, exist_ok=True)
                continue
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            f.seek(lba * SEC)
            with open(dst, 'wb') as o:
                left = sz
                while left:
                    b = f.read(min(left, 1 << 20))
                    if not b:
                        break
                    o.write(b)
                    left -= len(b)
        print("extracted", len(entries), file=sys.stderr)

main()
