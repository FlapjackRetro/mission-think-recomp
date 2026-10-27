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
#   * halve mouse coordinates in the child-window proc (FUN_004b46a1) and in the engine's current-message copy (FUN_004b1762: the
#     hotspot/cursor hit-tests read the position from the pump's raw lParam - unhalved they only matched in the top-left 640x480),
#   * scale the rects/regions the engine hands to InvalidateRect and SelectClipRgn (clip regions on window DCs are in
#     virtual units; unscaled they crop every 2x blit to the top-left 640x480 - the "splash drawn in the corner" bug).
WINDOW_HEX = (
    "e94b000000e926010000e969010000e987010000e9a5010000e9c3010000e9dd"
    "010000e9fc010000e906020000e9e2020000e94e030000e9ef040000e9dd0100"
    "00e9b6030000e9fc030000e9c60400005589e583ec3053568b5d08a158195100"
    "85c0744a8b809e00000085c074408d55f05250e86ba3f3ffff35581951008d4d"
    "d051e82869f1ff83c4088b75d40375d80375dc0375fcc70300000000c7430400"
    "0000008b45f889430889730ceb66c745f000000000c745f400000000c745f800"
    "050000c745fcc00300006a01680000ca028d45f050e8f9a3f3ff8b75f82b75f0"
    "8b45fc2b45f48945e06a00e89fa2f3ff29f0d1f8890301f08943086a01e88da2"
    "f3ff2b45e0d1f8790231c08943040345e089430c89d85e5b89ec5dc36af0ff74"
    "2408e856a2f3ffc1e81e83e001c20400f7442410000000407438817c24140000"
    "00807404d1642414817c2418000000807404d1642418817c241c000000807404"
    "d164241c817c2420000000807404d1642420ff25b4975100ff742404e89bffff"
    "ff85c07410d1642408d164240cd1642410d1642414ff25cc965100ff742404e8"
    "78ffffff85c07410d164240cd1642410d1642414d1642418ff258c965100ff74"
    "2408e855ffffff85c07410d1642410d1642414d1642418d164241cff25a89751"
    "00ff742408ff742408ff154897510085c0740a8b4c2408d17908d1790cc20800"
    "ff742408ff742408ff15a896510085c074098b4c2408d139d17904c20800ff25"
    "a89651008b4c2408d121d16104ff25c8975100837c24040074178b4c24108b54"
    "240c85c9740bd122d1620483c20849ebf1ff742410ff742410ff742410ff7424"
    "10ff15d896510050837c240c0074178b4c24148b54241085c9740bd13ad17a04"
    "83c20849ebf158c21000833d61655900007568536875655900e8bb9df3ff89c3"
    "689565590053e8189df3ffa36565590068b465590053e8089df3ffa36d655900"
    "68c265590053e8f89cf3ffa371655900687f655900e87f9df3ff68a765590050"
    "e8de9cf3ffa369655900688a65590053e8ce9cf3ffa3616559005bc3e889ffff"
    "ffff742404ff1569655900f7d819c0f7d8c204005589e583ec2053ff7508e8d9"
    "ffffff85c074548b5d0cd1e38b4510d1e08945f48b4514d1e08945f08b4518d1"
    "e08945f86a03ff7508ff1565655900ff7528ff7518ff7514ff7524ff7520ff75"
    "1cff75f8ff75f0ff75f453ff7508ff15616559005b89ec5dc224005b89ec5dff"
    "25009651005589e583ec2053ff7508e868ffffff85c0745a8b5d0cd1e38b4510"
    "d1e08945f48b4514d1e08945f08b4518d1e08945f86a03ff7508ff1565655900"
    "ff7538ff7534ff7530ff752cff7528ff7524ff7520ff751cff75f8ff75f0ff75"
    "f453ff7508ff15d49551005b89ec5dc234005b89ec5dff25d49551005589e583"
    "ec108b450c85c074358b0801c9894df08b480401c9894df48b480801c9894df8"
    "8b480c01c9894dfcff75108d45f050ff7508ff15f896510089ec5dc20c0089ec"
    "5dff25f89651005589e553565783ec10837d0c000f84af000000ff7508e89afe"
    "ffff85c00f849f00000081ec000e000089e75768000e0000ff750cff156d6559"
    "0085c0743589c3d16710d16714d16718d1671c8b4f088d572085c97411d122d1"
    "6204d16208d1620c83c21049ebeb57536a00ff1571655900eb2a8d75e456ff75"
    "0cff15cc9551008b460c01c0508b460801c0508b460401c0508b0601c050ff15"
    "6096510085c0742189c656ff7508ff15a495510089c356ff152096510089d88d"
    "65f45f5e5b5dc208008d65f45f5e5b5dff25a49551000fbfc9d1f90fbfd2d1fa"
    "8955f8894dfce982b2f1ff5589e58b450c2d0002000083f80977170fbf4514d1"
    "f80fb7c00fbf4d16d1f9c1e11009c88945145d5589e581c43cffffffe949e1f1"
    "ff000000000000000000000000000000000000000067646933322e646c6c0075"
    "73657233322e646c6c0053747265746368426c74005365745374726574636842"
    "6c744d6f64650057696e646f7746726f6d444300476574526567696f6e446174"
    "6100457874437265617465526567696f6e00"
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
                     (0x4D01BB, "d4955100", 50),
                     (0x4D036B, "f8965100", 65),     # InvalidateRect -> scale virtual rect
                     (0x4D0173, "a4955100", 70)):    # SelectClipRgn  -> scale virtual region on window DCs
    patch(va2off(va), bytes.fromhex("ff25" + iat), jmp(va, S + off) + b"\xcc")
patch(va2off(0x4B46A1), bytes.fromhex("558bec81c43cffffff"), jmp(0x4B46A1, S + 55) + b"\xcc" * 4)  # mouse
# the hit-test code's mouse-position getter (FUN_004b1762) reads the raw, unhalved lParam of the engine's current-message
# copy: halve it there (0x4b17a1: movswl ecx,cx; movswl edx,dx; mov [ebp-8],edx; mov [ebp-4],ecx  ->  jmp msgpt_fix)
patch(va2off(0x4B17A1), bytes.fromhex("0fbfc90fbfd28955f8894dfc"), jmp(0x4B17A1, S + 75) + b"\x90" * 7)
# non-client mouse re-posts convert screen->client themselves and re-enter the proc: use the unscaled ScreenToClient
for va in (0x4B4999, 0x4B4F73):
    o = va2off(va)
    assert d[o] == 0xE8 and va + 5 + struct.unpack_from("<i", d, o + 1)[0] == 0x4D02F3, hex(va)
    d[o:o + 5] = call(va, S + 60)
open(dst, "wb").write(d)
for l, p in (("original", src), ("patched ", dst)):
    print(l, hashlib.sha256(open(p, "rb").read()).hexdigest())
