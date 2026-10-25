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

## Repository contents
- `tools/`  patch + conversion tools (`build_game.py` builds a ready folder from your own `MISSION_CD.iso`)
- `config/` portable config files copied next to the game (`tlc.ini`, `SSMWINCD.INI`, `Play.bat`)
- No game data or executables are committed (copyrighted). Original `SSMWIN32.EXE` sha256
  `5e6a08f7306e70d7fb9298bceed854382bcbae052548312d3375ef61791b52d1`; patched build is reproducible with `tools/patch_exe.py`.
- Status: static analysis only, **never run on Windows**. Build script itself is untested end to end.
