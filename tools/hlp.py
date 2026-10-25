#!/usr/bin/env python3
"""Minimal WinHelp (.HLP, Win 3.x / 4.0) reader: internal directory + B+trees."""
import struct, sys


class Hlp:
    def __init__(self, path):
        self.d = open(path, 'rb').read()
        magic, self.dirstart, _free, self.size = struct.unpack_from('<IiiI', self.d, 0)
        assert magic == 0x00035F3F, hex(magic)
        self.files = {}
        self._read_dir()

    # -- internal file at offset: 9-byte header then data
    def _file_at(self, off):
        reserved, used, flags = struct.unpack_from('<IIB', self.d, off)
        return self.d[off + 9: off + 9 + used]

    def _btree_entries(self, data, entry_fmt):
        (magic, flags, pagesize) = struct.unpack_from('<HHH', data, 0)
        assert magic == 0x293B, hex(magic)
        structure = data[6:22]
        (_z, _splits, root, _neg1, totpages, nlevels, totentries) = struct.unpack_from('<HHHHHHI', data, 22)
        pages = data[38:]
        out = []
        if totentries == 0 or root == 0xFFFF:
            return out, structure
        page = root
        for _ in range(nlevels - 1):
            off = page * pagesize
            _unused, n, prev = struct.unpack_from('<HHH', pages, off)
            page = prev
        while page != 0xFFFF:
            off = page * pagesize
            _unused, n, prev, nxt = struct.unpack_from('<HHhH', pages, off)[0:4]
            p = off + 8
            for _ in range(n):
                ent, p = entry_fmt(pages, p)
                out.append(ent)
            page = nxt & 0xFFFF
            if page == 0xFFFF:
                break
        return out, structure

    def _read_dir(self):
        data = self._file_at(self.dirstart)

        def ent(b, p):
            e = b.index(b'\0', p)
            name = b[p:e].decode('latin1')
            off = struct.unpack_from('<i', b, e + 1)[0]
            return (name, off), e + 5
        entries, _ = self._btree_entries(data, ent)
        for n, o in entries:
            self.files[n] = o

    def get(self, name):
        return self._file_at(self.files[name])

    def btree(self, name, entry_fmt):
        return self._btree_entries(self.get(name), entry_fmt)[0]


if __name__ == '__main__':
    for p in sys.argv[1:]:
        h = Hlp(p)
        print(p, len(h.files))
        for n, o in sorted(h.files.items(), key=lambda x: x[1]):
            print('  %-18s off=%-7d size=%d' % (n, o, len(h.get(n))))
