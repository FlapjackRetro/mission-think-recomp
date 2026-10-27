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
# Patch 4 - scaled window: 640x480 / 800x600 / 1024x768 / 1280x960 / 1600x1200 client, picked at startup (default: last choice).  Source: tools/window_patch.asm (nasm -f bin, org 0x596000, embedded).
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
    "e94b000000e9b5010000e9da010000e902020000e92a020000e952020000e981"
    "020000e9b4020000e9cd020000e9c7030000e94c040000e968060000e9950200"
    "00e9cd040000e922050000e9370600005589e583ec3053568b5d08a158195100"
    "85c0744a8b809e00000085c074408d55f05250e86ba3f3ffff35581951008d4d"
    "d051e82869f1ff83c4088b75d40375d80375dc0375fcc70300000000c7430400"
    "0000008b45f889430889730ceb76c745f000000000c745f400000000833db86a"
    "5900007505e818060000a1b86a59008945f8a1bc6a59008945fc6a01680000ca"
    "028d45f050e8e9a3f3ff8b75f82b75f08b45fc2b45f48945e06a00e88fa2f3ff"
    "29f0d1f8890301f08943086a01e87da2f3ff2b45e0d1f8790231c08943040345"
    "e089430c89d85e5b89ec5dc3833db86a5900007505e8a805000052510faf05b8"
    "6a590089c2c1fa1fb94001000031d129d101c899b980020000f7f9595ac3833d"
    "b86a5900007505e8760500005269c08002000099f73db86a59005ac350535681"
    "3a00000080742081390000008074188b02e896ffffff89c68b020301e88bffff"
    "ff29f0890189325e5b58c36af0ff742408e8c7a1f3ffc1e81e83e001c20400f7"
    "44241000000040741a8d5424148d4c241ce8a6ffffff8d5424188d4c2420e899"
    "ffffffff25b4975100ff742404e8b9ffffff85c0741a8d5424088d4c2410e879"
    "ffffff8d54240c8d4c2414e86cffffffff25cc965100ff742404e88cffffff85"
    "c0741a8d54240c8d4c2414e84cffffff8d5424108d4c2418e83fffffffff258c"
    "965100ff742408e85fffffff85c0741a8d5424108d4c2418e81fffffff8d5424"
    "148d4c241ce812ffffffff25a8975100ff742408ff742408ff154897510085c0"
    "741f8b4c24088b4108e8d0feffff8941088b410ce8c5feffff89410cb8010000"
    "00c20800ff742408ff742408ff15a896510085c0741d8b4c24088b01e89dfeff"
    "ff89018b4104e893feffff894104b801000000c20800ff25a89651008b4c2408"
    "8b01e845feffff89018b4104e83bfeffff894104ff25c8975100837c24040074"
    "268b4c24108b54240c85c9741a8b02e818feffff89028b4204e80efeffff8942"
    "0483c20849ebe2ff742410ff742410ff742410ff742410ff15d896510050837c"
    "240c0074268b4c24148b54241085c9741a8b02e806feffff89028b4204e8fcfd"
    "ffff89420483c20849ebe258c21000833d1f6c59000075685368336c5900e8d6"
    "9cf3ff89c368536c590053e8339cf3ffa3236c590068726c590053e8239cf3ff"
    "a32b6c590068806c590053e8139cf3ffa32f6c5900683d6c5900e89a9cf3ff68"
    "656c590050e8f99bf3ffa3276c590068486c590053e8e99bf3ffa31f6c59005b"
    "c3e889ffffffff742404ff15276c5900f7d819c0f7d8c204005589e583ec2053"
    "ff7508e8d9ffffff85c0746d8b450ce818fdffff89c38b450c034514e80bfdff"
    "ff29d88945f08b4510e8fefcffff8945f48b4510034518e8f0fcffff2b45f489"
    "45f86a03ff7508ff15236c5900ff7528ff7518ff7514ff7524ff7520ff751cff"
    "75f8ff75f0ff75f453ff7508ff151f6c59005b89ec5dc224005b89ec5dff2500"
    "9651005589e583ec2053ff7508e84fffffff85c074738b450ce88efcffff89c3"
    "8b450c034514e881fcffff29d88945f08b4510e874fcffff8945f48b45100345"
    "18e866fcffff2b45f48945f86a03ff7508ff15236c5900ff7538ff7534ff7530"
    "ff752cff7528ff7524ff7520ff751cff75f8ff75f0ff75f453ff7508ff15d495"
    "51005b89ec5dc234005b89ec5dff25d49551005589e583ec10538b5d0c85db74"
    "428b03e804fcffff8945f08b4304e8f9fbffff8945f48b4308e8eefbffff8945"
    "f88b430ce8e3fbffff8945fcff75108d45f050ff7508ff15f89651005b89ec5d"
    "c20c005b89ec5dff25f89651005589e553565783ec10837d0c000f84fa000000"
    "ff7508e859feffff85c00f84ea00000081ec000e000089e75768000e0000ff75"
    "0cff152b6c590085c0747489c38b4710e877fbffff8947108b4714e86cfbffff"
    "8947148b4718e861fbffff8947188b471ce856fbffff89471c8b4f088d572085"
    "c974308b02e842fbffff89028b4204e838fbffff8942048b4208e82dfbffff89"
    "42088b420ce822fbffff89420c83c21049ebcc57536a00ff152f6c5900eb368d"
    "75e456ff750cff15cc9551008b460ce8f8faffff508b4608e8effaffff508b46"
    "04e8e6faffff508b06e8defaffff50ff156096510085c0742189c656ff7508ff"
    "15a495510089c356ff152096510089d88d65f45f5e5b5dc208008d65f45f5e5b"
    "5dff25a4955100500fbfc1e8cefaffff8945fc0fbfc2e8c3faffff8945f858e9"
    "09b1f1ff5589e58b450c2d0002000083f809771f0fbf4516e8a1faffffc1e010"
    "89c10fbf4514e893faffff0fb7c009c88945145d5589e581c43cffffffe9c8df"
    "f1ff60c705b86a590000050000c705bc6a5900c0030000681f6b5900e85899f3"
    "ff89c3bed76b5900e8cb000000683d6c5900e84299f3ff89c3beeb6b5900e8b5"
    "00000068036b5900680005000068156b5900680d6b5900ff152c6b5900c705c0"
    "6a59000300000031c983f90573123b048dc46a59007506890dc06a590041ebe9"
    "68036b59006a01681b6b5900680d6b5900ff152c6b590085c0743f6a0068f067"
    "59006a0068a06859006800004000ff15346b590085c07e2248a3c06a59006803"
    "6b5900ff3485d86a590068156b5900680d6b5900ff15306b5900a1c06a59008b"
    "0485c46a5900a3b86a59008d0440c1e802a3bc6a590061c38b0685c074115053"
    "e8de97f3ff8b7e04890783c608ebe9c38b4424083d10010000740c3d11010000"
    "743b31c0c21000538b5c2408a1c06a590083c065506a696a6553ff153c6b5900"
    "a1c06a590083c0655053ff15446b590050ff15486b59005b31c0c210000fb744"
    "240c83f801741e83f802740531c0c210006a00ff742408ff15386b5900b80100"
    "0000c2100053568b5c240c31f68d46655053ff15406b590085c0750c4683fe05"
    "72eb8b35c06a59008d46015053ff15386b59005e5bb801000000c21000000000"
    "c00ac88000000000070000000000a0007000000000004d006900730073006900"
    "6f006e00200054002e0048002e0049002e004e002e004b002e0020002d002000"
    "44006900730070006c00610079002000530069007a006500000008004d005300"
    "20005300680065006c006c00200044006c006700000000000000005000000000"
    "0a0008008c000a00ffffffff8200430068006f006f0073006500200074006800"
    "65002000770069006e0064006f0077002000730069007a0065003a0000000000"
    "09000350000000001000180082000c006500ffff800036003400300020007800"
    "2000340038003000200020002800310078002900000000000900015000000000"
    "1000260082000c006600ffff8000380030003000200078002000360030003000"
    "20002000280031002e0032003500780029000000000000000900015000000000"
    "1000340082000c006700ffff8000310030003200340020007800200037003600"
    "380020002000280031002e003600780029000000000000000900015000000000"
    "1000420082000c006800ffff8000310032003800300020007800200039003600"
    "3000200020002800320078002900000000000000090001500000000010005000"
    "82000c006900ffff800031003600300030002000780020003100320030003000"
    "20002000280032002e003500780029000000000001000150000000003c005f00"
    "28000e000100ffff800053007400610072007400000000000000000000000000"
    "030000008002000020030000000400000005000040060000ec6a5900f06a5900"
    "f46a5900f96a5900fe6a59003634300038303000313032340031323830003136"
    "3030002e5c746c632e696e6900446973706c61790057696474680041736b006b"
    "65726e656c33322e646c6c000000000000000000000000000000000000000000"
    "0000000000000000000000004765745072697661746550726f66696c65496e74"
    "410057726974655072697661746550726f66696c65537472696e674100446961"
    "6c6f67426f78496e646972656374506172616d4100456e644469616c6f670043"
    "6865636b526164696f427574746f6e004973446c67427574746f6e436865636b"
    "656400476574446c674974656d00536574466f637573004c6b59002c6b590062"
    "6b5900306b5900000000007d6b5900346b5900956b5900386b59009f6b59003c"
    "6b5900b06b5900406b5900c36b5900446b5900ce6b5900486b59000000000000"
    "0000000000000000000000000000000000000067646933322e646c6c00757365"
    "7233322e646c6c0053747265746368426c740053657453747265746368426c74"
    "4d6f64650057696e646f7746726f6d444300476574526567696f6e4461746100"
    "457874437265617465526567696f6e00"
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
