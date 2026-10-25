#!/usr/bin/env python3
"""Build the Windows-ready game folder from your own copy of the disc.

usage: build_game.py MISSION_CD.iso OUTDIR      (needs Python 3, Pillow, nasm)
Extracts the ISO (isoread.py), copies the Win32 game files (no Mac data, no installers), applies
patch_exe.py to SSMWIN32.EXE, converts DATA/WIN/*.HLP to HTML (hlp2html.py) and adds config/.
"""
import os, shutil, subprocess, sys, tempfile
here = os.path.dirname(os.path.abspath(__file__))
iso, out = sys.argv[1:3]
tmp = tempfile.mkdtemp()
subprocess.run([sys.executable, os.path.join(here, 'isoread.py'), 'extract', iso, tmp], check=True)
os.makedirs(out, exist_ok=True)
shutil.copytree(os.path.join(tmp, 'DATA'), os.path.join(out, 'DATA'), dirs_exist_ok=True,
                ignore=shutil.ignore_patterns('MAC'))
for f in ('SMACKW32.DLL', 'MISSION.DAT', 'LICENSE.TXT', 'MT.ICO'):
    shutil.copy(os.path.join(tmp, f), out)
subprocess.run([sys.executable, os.path.join(here, 'patch_exe.py'),
                os.path.join(tmp, 'SSMWIN32.EXE'), os.path.join(out, 'SSMWIN32.EXE')], check=True)
for n in ('MISSION', 'TWOPLAY', 'CREDITS'):
    subprocess.run([sys.executable, os.path.join(here, 'hlp2html.py'),
                    os.path.join(out, 'DATA', 'WIN', n + '.HLP'),
                    os.path.join(out, 'DATA', 'WIN', n.lower() + '.htm'),
                    os.path.join(out, 'DATA', 'WIN', 'helpimg'), 'helpimg/'], check=True)
for f in os.listdir(os.path.join(here, '..', 'config')):
    shutil.copy(os.path.join(here, '..', 'config', f), out)
shutil.rmtree(tmp)
print('done:', out)
