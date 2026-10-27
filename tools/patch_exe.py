#!/usr/bin/env python3
"""Patch SSMWIN32.EXE for Windows 11 / portable use.  Usage: patch_exe.py ORIGINAL PATCHED

Patch 1 - free-disk-space check (VA 0x0041d224, file 0x1c824): JGE -> JMP (32-bit IMUL overflow
          on big drives makes the 10 MB check fail spuriously).
Patch 3 - WinHelp replacement (see below)
Patch 2 - portable config: the two "tlcapps.ini" literals (VA 0x4de01e, 0x4de094; file 0xDCC1E,
          0xDCC94) become ".\\tlc.ini". A name containing a path is resolved against the current
          directory instead of %WINDIR%, so no admin rights / C:\\Windows\\tlcapps.ini are needed.
"""
import hashlib, struct, sys
src, dst = sys.argv[1:3]
d = bytearray(open(src, "rb").read())
def patch(off, old, new):
    assert len(old) == len(new), (len(old), len(new))
    if d[off:off+len(old)] != old:
        sys.exit(f"unexpected bytes at 0x{off:x}: {bytes(d[off:off+len(old)])!r}")
    d[off:off+len(new)] = new
patch(0x1C824, bytes.fromhex("7d1dff35a0a04d00"), bytes.fromhex("eb1dff35a0a04d00"))
old = b"tlcapps.ini\0"
new = b".\\tlc.ini\0\0\0"
for off in (904222, 904340):
    patch(off, old, new)
# Patch 3 - WinHelp replacement (WinHelp/.hlp is gone in Windows 10/11).
# Code cave: 152 zero bytes at the end of the CODE section (VA 0x4d0568, file 0xCFB68) hold a 122-byte
# stdcall WinHelpA replacement (tools/winhelp_shim.asm) that turns "...\x.hlp" into "...\x.htm" and
# opens it with ShellExecuteA. The WinHelpA import thunk (VA 0x4d03ef, file 0xCF9EF) is redirected to it.
# Assembled from winhelp_shim.asm (nasm -f bin, org 0x4d0568); embedded so nasm is not needed to build.
SHIM_HEX = (
    "5589e5837d100274528b4d0c803900740341ebf88079ff7075148079fe6c750e"
    "8079fd687508c641fe74c641ff6d68cc054d00e847faffff85c0741f68d4054d"
    "0050e814faffff85c074106a016a006a00ff750c6a00ff7508ffd0b801000000"
    "5dc210007368656c6c3332005368656c6c457865637574654100"
)
shim = bytes.fromhex("".join(SHIM_HEX.split()))
assert len(shim) <= 152, len(shim)
patch(0xCFB68, b"\0" * len(shim), shim)
rel = 0x4D0568 - (0x4D03EF + 5)
patch(0xCF9EF, bytes.fromhex("ff2550975100"), b"\xe9" + struct.pack("<i", rel) + b"\xcc")
open(dst, "wb").write(d)
for l, p in (("original", src), ("patched ", dst)):
    print(l, hashlib.sha256(open(p, "rb").read()).hexdigest())
