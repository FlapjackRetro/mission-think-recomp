import struct
OPLEN = {0x80: 2, 0x81: 0, 0x82: 0, 0x83: 0, 0x89: 0, 0x8b: 0, 0x8c: 0,
         0x86: 8, 0x87: 8, 0x88: 8, 0xe2: 4, 0xe3: 4, 0xe6: 4, 0xe7: 4}

def try_parse(l1, start, n):
    p = start; cmds = []
    for i in range(n):
        if p >= len(l1): return None
        c = l1[p]
        if c == 0xff:
            if i != n-1 or p != len(l1)-1: return None
            cmds.append((c, b'')); p += 1; continue
        if c not in OPLEN: return None
        ol = OPLEN[c]
        if p + 1 + ol > len(l1): return None
        cmds.append((c, bytes(l1[p+1:p+1+ol]))); p += 1 + ol
    if p != len(l1): return None
    return cmds

def split_cmds(l1, l2):
    strs = l2.split(b'\0')
    # l2 ends with NUL after every string: last element empty from final split
    strs = strs[:-1]
    n = len(strs)
    sols = []
    for s in range(len(l1)):
        r = try_parse(l1, s, n)
        if r: sols.append((s, r))
    return strs, sols
