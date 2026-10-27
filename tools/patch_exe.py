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
# Patch 4 - fixed 2x window (1280x960 client).  Source: tools/window_patch.asm (nasm -f bin, org 0x596000, embedded).
# The game is virtualised to a 640x480 world: a new RWX PE section ".mtk" holds shims that
#   * make the frame a normal captioned window (style imm at VA 0x4ac742) with a 1280x960 client area,
#   * redirect FUN_004b0150 (the "screen rect" helper) so layout still sees a 640x480 (virtual) frame,
#   * scale child-window creation/move/size (CreateWindowExA, MoveWindow, SetWindowPos, DeferWindowPos) by 2,
#   * scale client coordinates back down (GetClientRect, ScreenToClient, ClientToScreen, MapWindowPoints),
#   * stretch BitBlt/StretchDIBits aimed at window DCs by 2 (COLORONCOLOR = clean pixel doubling),
#   * halve mouse coordinates in the child-window proc (FUN_004b46a1).
WINDOW_HEX = (
    "e93c000000e917010000e95a010000e978010000e996010000e9b4010000e9ce"
    "010000e9ed010000e9f7010000e9b1020000e91d030000e98f030000e9ce0100"
    "005589e583ec3053568b5d08a15819510085c0744a8b809e00000085c074408d"
    "55f05250e87aa3f3ffff35581951008d4dd051e83769f1ff83c4088b75d40375"
    "d80375dc0375fcc70300000000c74304000000008b45f889430889730ceb66c7"
    "45f000000000c745f400000000c745f800050000c745fcc00300006a01680000"
    "ca028d45f050e808a4f3ff8b75f82b75f08b45fc2b45f48945e06a00e8aea2f3"
    "ff29f0d1f8890301f08943086a01e89ca2f3ff2b45e0d1f8790231c089430403"
    "45e089430c89d85e5b89ec5dc36af0ff742408e865a2f3ffc1e81e83e001c204"
    "00f7442410000000407438817c2414000000807404d1642414817c2418000000"
    "807404d1642418817c241c000000807404d164241c817c2420000000807404d1"
    "642420ff25b4975100ff742404e89bffffff85c07410d1642408d164240cd164"
    "2410d1642414ff25cc965100ff742404e878ffffff85c07410d164240cd16424"
    "10d1642414d1642418ff258c965100ff742408e855ffffff85c07410d1642410"
    "d1642414d1642418d164241cff25a8975100ff742408ff742408ff1548975100"
    "85c0740a8b4c2408d17908d1790cc20800ff742408ff742408ff15a896510085"
    "c074098b4c2408d139d17904c20800ff25a89651008b4c2408d121d16104ff25"
    "c8975100837c24040074178b4c24108b54240c85c9740bd122d1620483c20849"
    "ebf1ff742410ff742410ff742410ff742410ff15d896510050837c240c007417"
    "8b4c24148b54241085c9740bd13ad17a0483c20849ebf158c21000833d016459"
    "00007546680d645900e8cb9df3ff50682d64590050e8299df3ffa30564590058"
    "682264590050e8189df3ffa3016459006817645900e89f9df3ff683f64590050"
    "e8fe9cf3ffa309645900c3e8abffffffff742404ff1509645900f7d819c0f7d8"
    "c204005589e583ec2053ff7508e8d9ffffff85c074548b5d0cd1e38b4510d1e0"
    "8945f48b4514d1e08945f08b4518d1e08945f86a03ff7508ff1505645900ff75"
    "28ff7518ff7514ff7524ff7520ff751cff75f8ff75f0ff75f453ff7508ff1501"
    "6459005b89ec5dc224005b89ec5dff25009651005589e583ec2053ff7508e868"
    "ffffff85c0745a8b5d0cd1e38b4510d1e08945f48b4514d1e08945f08b4518d1"
    "e08945f86a03ff7508ff1505645900ff7538ff7534ff7530ff752cff7528ff75"
    "24ff7520ff751cff75f8ff75f0ff75f453ff7508ff15d49551005b89ec5dc234"
    "005b89ec5dff25d49551005589e58b450c2d0002000083f80977170fbf4514d1"
    "f80fb7c00fbf4d16d1f9c1e11009c88945145d5589e581c43cffffffe9a9e2f1"
    "ff00000000000000000000000067646933322e646c6c007573657233322e646c"
    "6c0053747265746368426c740053657453747265746368426c744d6f64650057"
    "696e646f7746726f6d444300"
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
def call(frm, to): return b"\xe8" + struct.pack("<i", to - (frm + 5))
S = 0x596000
patch(va2off(0x4AC742), bytes.fromhex("00000a82"), bytes.fromhex("0000ca02"))   # frame style 0x02CA0000
patch(va2off(0x4B0150), bytes.fromhex("558bec83c4"), jmp(0x4B0150, S))              # screen rect
patch(va2off(0x4ADB49), bytes.fromhex("837dd8000f"), jmp(0x4ADB49, 0x4AE272))      # drop old WM_SIZE child stretch
# import thunks (jmp [iat]) -> shims.  (thunk VA, expected bytes, shim entry offset)
for va, iat, off in ((0x4D0485, "b4975100", 5), (0x4D0329, "cc965100", 10), (0x4D02C9, "8c965100", 15),
                     (0x4D0473, "a8975100", 20), (0x4D03E3, "48975100", 25), (0x4D02F3, "a8965100", 30),
                     (0x4D04A3, "c8975100", 35), (0x4D033B, "d8965100", 40), (0x4D01FD, "00965100", 45),
                     (0x4D01BB, "d4955100", 50)):
    patch(va2off(va), bytes.fromhex("ff25" + iat), jmp(va, S + off) + b"\xcc")
patch(va2off(0x4B46A1), bytes.fromhex("558bec81c43cffffff"), jmp(0x4B46A1, S + 55) + b"\xcc" * 4)  # mouse
# non-client mouse re-posts convert screen->client themselves and re-enter the proc: use the unscaled ScreenToClient
for va in (0x4B4999, 0x4B4F73):
    o = va2off(va)
    assert d[o] == 0xE8 and va + 5 + struct.unpack_from("<i", d, o + 1)[0] == 0x4D02F3, hex(va)
    d[o:o + 5] = call(va, S + 60)
open(dst, "wb").write(d)
for l, p in (("original", src), ("patched ", dst)):
    print(l, hashlib.sha256(open(p, "rb").read()).hexdigest())
