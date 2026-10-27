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
# Patch 4 - resizable window (see tools/window_patch.asm; assembled with nasm -f bin, org 0x596000, embedded).
# The game builds its frame as a borderless-style popup (mode 3) sized to the screen and centres a 640x480
# stage child in it using FUN_004b0150 (= "screen rect"). We
#   a) append a new RWX PE section ".mtk" (VA 0x596000) holding replacement code,
#   b) make the frame a normal WS_OVERLAPPEDWINDOW (style imm at VA 0x4ac742),
#   c) redirect FUN_004b0150 to return the frame's client size (or a centred 640x480 outer rect before the
#      frame exists), so the existing centring maths keeps the stage centred in whatever size the window is,
#   d) replace the old WM_SIZE child-stretching code (VA 0x4adb49) with a call to the game's own
#      re-centre routine (FUN_00424354).
WINDOW_HEX = (
    "5589e583ec3053568b5d08a15819510085c0744a8b809e00000085c074408d55"
    "f05250e8bba3f3ffff35581951008d4dd051e87869f1ff83c4088b75d40375d8"
    "0375dc0375fcc70300000000c74304000000008b45f889430889730ceb62c745"
    "f000000000c745f400000000c745f880020000c745fce00100006a01680000cf"
    "028d45f050e849a4f3ff8b75f82b75f08b45fc2b45f48945e06a00e8efa2f3ff"
    "29f0d1f8890301f08943086a01e8dda2f3ff2b45e0d1f88943040345e089430c"
    "89d85e5b89ec5dc3833d5819510000740e833d50315100007405e875e2e8ffe9"
    "8e81f1ff"
)
WM_SIZE_OFF = 200

code = bytes.fromhex("".join(WINDOW_HEX.split()))
SEC_RVA, SEC_RAW = 0x196000, 0x18B000
assert len(d) == 0x18AEC7, hex(len(d))
d += b"\0" * (SEC_RAW - len(d)) + code + b"\0" * (0x200 - len(code))
pe = struct.unpack_from("<I", d, 0x3C)[0]
assert struct.unpack_from("<H", d, pe + 6)[0] == 8
struct.pack_into("<H", d, pe + 6, 9)
opt = pe + 24
assert struct.unpack_from("<I", d, opt + 56)[0] == 0x196000
struct.pack_into("<I", d, opt + 56, 0x197000)
sec = opt + 224 + 8 * 40
assert d[sec:sec + 40] == b"\0" * 40
d[sec:sec + 40] = b".mtk\0\0\0\0" + struct.pack("<IIIIIIHHI", 0x1000, SEC_RVA, 0x200, SEC_RAW, 0, 0, 0, 0, 0xE0000060)
def va2off(va): return va - 0x400A00
def jmp(frm, to): return b"\xe9" + struct.pack("<i", to - (frm + 5))
patch(va2off(0x4AC742), bytes.fromhex("00000a82"), bytes.fromhex("0000cf02"))
patch(va2off(0x4B0150), bytes.fromhex("55 8b ec 83 c4".replace(" ", "")), jmp(0x4B0150, 0x596000))
patch(va2off(0x4ADB49), bytes.fromhex("837dd8000f"), jmp(0x4ADB49, 0x596000 + WM_SIZE_OFF))
open(dst, "wb").write(d)
for l, p in (("original", src), ("patched ", dst)):
    print(l, hashlib.sha256(open(p, "rb").read()).hexdigest())
