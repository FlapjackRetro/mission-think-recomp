import struct
from hlp import Hlp

def records(h, blocksize=4096):
    t = h.get('|TOPIC')
    data = bytearray()
    for b in range(0, len(t), blocksize):
        data += t[b+12:b+blocksize]
    data = bytes(data)
    pos = 0
    out = []
    while pos + 21 <= len(data):
        bs, dl2, prev, nxt, dl1, rt = struct.unpack_from('<iiiiiB', data, pos)
        if bs < 21 or pos + bs > len(data):
            break
        l1 = data[pos+21:pos+dl1]
        l2 = data[pos+dl1:pos+bs]
        out.append(dict(pos=pos, bs=bs, dl2=dl2, prev=prev, next=nxt, rt=rt, l1=l1, l2=l2))
        pos += bs
    return out, len(data)

if __name__ == '__main__':
    import sys
    h = Hlp(sys.argv[1])
    rs, n = records(h)
    print(len(rs), 'records of', n, 'bytes')
    for r in rs[:int(sys.argv[2]) if len(sys.argv) > 2 else 12]:
        print(hex(r['pos']), 'rt=%02x'%r['rt'], 'dl2=%d'%r['dl2'], 'l1=', r['l1'].hex(), 'l2=', r['l2'])
