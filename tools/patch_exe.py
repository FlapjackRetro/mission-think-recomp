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
    "e919000000e9dc000000e952020000e903030000e915040000e95e0400005589"
    "e583ec3053568b5d08a15819510085c0744a8b809e00000085c074408d55f052"
    "50e89da3f3ffff35581951008d4dd051e85a69f1ff83c4088b75d40375d80375"
    "dc0375fcc70300000000c74304000000008b45f889430889730ceb62c745f000"
    "000000c745f400000000c745f880020000c745fce00100006a01680000cf028d"
    "45f050e82ba4f3ff8b75f82b75f08b45fc2b45f48945e06a00e8d1a2f3ff29f0"
    "d1f8890301f08943086a01e8bfa2f3ff2b45e0d1f88943040345e089430c89d8"
    "5e5b89ec5dc3833d5819510000740e833d50315100007405e805000000e97081"
    "f1ff5589e583ec2053a1581951008b809e00000085c00f84850000008d55f052"
    "50e8bda2f3ff8b45f88b4dfc85c07e7185c97e6d8945e8894dec8d1440c1ea02"
    "89c339ca7e1889ca8d1c8d0000000089d831d2bb03000000f7f389c389ca895d"
    "e08955e4a1503151008b808000000085c0742e89c38b45ec2b45e4d1f88b4de8"
    "2b4de0d1f96a14ff75e4ff75e050516a0053e832a1f3ff6a006a0053e8caa1f3"
    "ff5b89ec5dc3833d9e64590000754668aa645900e8a09ef3ff5068ca64590050"
    "e8fe9df3ffa3a26459005868bf64590050e8ed9df3ffa39e64590068b4645900"
    "e8749ef3ff68dc64590050e8d39df3ffa3a6645900c35589e583ec1053e8a4ff"
    "ffffa15031510085c0744d8b988000000085db7443ff7508ff15a664590039d8"
    "75368d55f05253e8b7a1f3ff8b45f88b4dfc85c07e2285c97e1e3d8002000075"
    "0881f9e0010000740f8b550c8902894a04b801000000eb0231c05b89ec5dc208"
    "005589e583ec205356578d45e850ff7508e880ffffff85c00f848d0000008b75"
    "e88b7decb9800200008b450c0fafc699f7f989c38b450c0345140fafc6057f02"
    "000099f7f929d88945f0b9e00100008b45100fafc799f7f98945f48b45100345"
    "180fafc705df01000099f7f92b45f48945f86a03ff7508ff15a2645900ff7528"
    "ff7518ff7514ff7524ff7520ff751cff75f8ff75f0ff75f453ff7508ff159e64"
    "59005f5e5b89ec5dc224005f5e5b89ec5dff25009651005589e583ec20535657"
    "8d45e850ff7508e8cafeffff85c00f84930000008b75e88b7decb9800200008b"
    "450c0fafc699f7f989c38b450c0345140fafc6057f02000099f7f929d88945f0"
    "b9e00100008b45100fafc799f7f98945f48b45100345180fafc705df01000099"
    "f7f92b45f48945f86a03ff7508ff15a2645900ff7538ff7534ff7530ff752cff"
    "7528ff7524ff7520ff751cff75f8ff75f0ff75f453ff7508ff15d49551005f5e"
    "5b89ec5dc234005f5e5b89ec5dff25d49551005589e583ec1053a15031510085"
    "c074448b80800000003b450875398d55f05250e8eb9ff3ff8b5d0c8b4df885c9"
    "7e25837dfc007e1f8b0369c08002000099f7f989038b4dfc8b430469c0e00100"
    "0099f7f98943045b89ec5dc208005589e583ec088b450c2d0002000083f80977"
    "2a0fbf45148945f80fbf45168945fc8d45f850ff7508e878ffffff0fb745f80f"
    "b74dfcc1e11009c889451489ec5d5589e581c43cffffffe92ee2f1ffff742408"
    "ff742408e86a9ef3ffff742408ff742408e83dffffffb801000000c208000000"
    "0000000000000000000067646933322e646c6c007573657233322e646c6c0053"
    "747265746368426c740053657453747265746368426c744d6f64650057696e64"
    "6f7746726f6d444300"
)
code = bytes.fromhex("".join(WINDOW_HEX.split()))
SEC_RVA, SEC_RAW = 0x196000, 0x18B000
assert len(d) == 0x18AEC7, hex(len(d))
RAWSZ = (len(code) + 0x1FF) & ~0x1FF
assert RAWSZ <= 0x1000
d += b"\0" * (SEC_RAW - len(d)) + code + b"\0" * (RAWSZ - len(code))
pe = struct.unpack_from("<I", d, 0x3C)[0]
assert struct.unpack_from("<H", d, pe + 6)[0] == 8
struct.pack_into("<H", d, pe + 6, 9)
opt = pe + 24
assert struct.unpack_from("<I", d, opt + 56)[0] == 0x196000
struct.pack_into("<I", d, opt + 56, 0x197000)
sec = opt + 224 + 8 * 40
assert d[sec:sec + 40] == b"\0" * 40
d[sec:sec + 40] = b".mtk\0\0\0\0" + struct.pack("<IIIIIIHHI", 0x1000, SEC_RVA, RAWSZ, SEC_RAW, 0, 0, 0, 0, 0xE0000060)
def va2off(va): return va - 0x400A00
def jmp(frm, to): return b"\xe9" + struct.pack("<i", to - (frm + 5))
patch(va2off(0x4AC742), bytes.fromhex("00000a82"), bytes.fromhex("0000cf02"))
patch(va2off(0x4B0150), bytes.fromhex("55 8b ec 83 c4".replace(" ", "")), jmp(0x4B0150, 0x596000))
patch(va2off(0x4ADB49), bytes.fromhex("837dd8000f"), jmp(0x4ADB49, 0x596005))
def call(frm, to): return b"\xe8" + struct.pack("<i", to - (frm + 5))
# Patch 5 - scale the 640x480 stage to the window (see window_patch.asm)
#   BitBlt / StretchDIBits import thunks -> shims that stretch blits aimed at the stage window's DC
patch(va2off(0x4D01FD), bytes.fromhex("ff2500965100"), jmp(0x4D01FD, 0x59600A) + b"\xcc")
patch(va2off(0x4D01BB), bytes.fromhex("ff25d4955100"), jmp(0x4D01BB, 0x59600F) + b"\xcc")
#   child-window proc (FUN_004b46a1): map mouse coordinates back to 640x480 before the game sees them
patch(va2off(0x4B46A1), bytes.fromhex("558bec81c43cffffff"), jmp(0x4B46A1, 0x596014) + b"\xcc" * 4)
#   cursor-position helper (FUN_004b3783): ScreenToClient -> ScreenToClient + scale
patch(va2off(0x4B37A9), bytes.fromhex("e845cb0100"), call(0x4B37A9, 0x596019))
open(dst, "wb").write(d)
for l, p in (("original", src), ("patched ", dst)):
    print(l, hashlib.sha256(open(p, "rb").read()).hexdigest())
