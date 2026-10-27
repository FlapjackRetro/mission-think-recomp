# Mission T.H.I.N.K. – Windows port workspace

Layout:
- game/   the game, installed without the setup program: patched SSMWIN32.EXE, SMACKW32.DLL, MISSION.DAT, DATA/ (Mac files removed), config files, Play.bat
- tools/  patch_exe.py (rebuilds SSMWIN32.EXE from the original), isoread.py (ISO9660 extractor)

Config is portable (no installer, no admin, nothing in C:\Windows):
- Patch 2 changes the exe's two "tlcapps.ini" strings to ".\tlc.ini" (path => relative to current dir).
- game/tlc.ini      [Mission: T.H.I.N.K.] Path=SSMWIN32.EXE   -> program dir = "" (cwd), MISSION.DAT in cwd
- game/SSMWINCD.INI [Mission: T.H.I.N.K.] CDDrive=.\DATA     -> data folder
- Start the game with its folder as the current directory (Play.bat or a shortcut with "Start in").

UNTESTED on Windows. Unverified assumption: the resource resolver (FUN_004a9add) accepts the relative
data path ".\DATA\". If "insert the CD" appears, set CDDrive to an absolute path in SSMWINCD.INI.
Exe patches: (1) 0x1c824 7D->EB free-space check; (2) 0xDCC1E and 0xDCC94 tlcapps.ini -> .\tlc.ini
Still to do: WinHelp (.HLP) replacement, sound-device check, palette/256-colour behaviour, test on Win11.

## Help system (patch 3)
WinHelp (.HLP) no longer exists on Windows 10/11. The game's only call is `WinHelpA` via thunk VA 0x4d03ef
(callers: FUN_00423f31, passing "WIN\mission.hlp" / "WIN\twoplay.hlp" / "WIN\credits.hlp" with
HELP_PARTIALKEY("Contents") or HELP_CONTEXT(n)).
- tools/hlp2html.py converts each .HLP to DATA/WIN/<name>.htm (+ DATA/WIN/helpimg/*.png). Own parser for the
  uncompressed WinHelp 3.1 format (internal dir, |TOPIC records, |FONT, |CONTEXT, MRB/SHG bitmaps with hotspots).
- tools/winhelp_shim.asm (122 bytes, in the 152-byte zero tail of CODE at VA 0x4d0568) replaces WinHelpA:
  ".hlp" -> ".htm" in the caller's path buffer, then ShellExecuteA (loaded via LoadLibrary/GetProcAddress).
  HELP_QUIT is ignored; HELP_CONTEXT ids are not honoured (every call opens the file's Contents topic).
- Topic link targets: |CONTEXT value order == topic order (rank), so hash -> topic = rank of its context value.
Untested in the real game.

## Fixed 2x window (patch 4)

The game is virtualised to its native 640x480 world and shown at 2x (1280x960 client area, normal captioned window,
not resizable yet). A new `.mtk` PE section (`tools/window_patch.asm`, embedded in `tools/patch_exe.py`) holds shims that
scale child-window creation/moves by 2, scale client coordinates back to 640x480 (GetClientRect, ScreenToClient,
ClientToScreen, MapWindowPoints), stretch BitBlt/StretchDIBits aimed at window DCs by 2, and halve mouse coordinates.
A freely resizable window is a later step.

Clip regions and invalidation rects are virtual too. The engine clips every window blit with `SelectClipRgn` using a
region in 640x480 units (e.g. `0,0,641,481` for a full repaint) and invalidates with a virtual rect from the hooked
`GetClientRect`. Unscaled, Windows treats these as real pixels, so each 2x-stretched blit was cropped to the top-left
640x480 - the opening splash (starfield / "The Learning Company" logo) showed up unscaled in the corner while later
screens looked fine. Two more shims fix it: `SelectClipRgn` on a window DC rebuilds the region at 2x
(`GetRegionData` -> scale -> `ExtCreateRegion`; bounding-box fallback for regions over 3.5 KB), and `InvalidateRect`
scales its rect. Entries +65 / +70 of the `.mtk` jump table; thunks VA 0x4D036B and 0x4D0173.
Hotspot hit-tests and cursor changes use a third source of mouse coordinates. Besides the child proc's `lParam` (halved
by `mouse_hook`) the engine keeps a copy of the pump's current message at 0x513338 and `FUN_004b1762` (the "mouse position"
getter behind the hover/cursor/click hit-tests, `FUN_004a3246`) reads x/y from that raw `lParam`. Unhalved, hotspots only
matched while the pointer was in the top-left 640x480 real pixels. `msgpt_fix` (entry +75) halves it at the read
(hook VA 0x4B17A1).
Status: verified on Windows 11 (splash, title card and intro fill the 1280x960 client area; button hover works everywhere).

## Repository contents
- `tools/`  patch + conversion tools (`build_game.py` builds a ready folder from your own `MISSION_CD.iso`)
- `config/` portable config files copied next to the game (`tlc.ini`, `SSMWINCD.INI`, `Play.bat`)
- No game data or executables are committed (copyrighted). Original `SSMWIN32.EXE` sha256
  `5e6a08f7306e70d7fb9298bceed854382bcbae052548312d3375ef61791b52d1`; patched build is reproducible with `tools/patch_exe.py`.
- Status: static analysis only, **never run on Windows**. Build script itself is untested end to end.
