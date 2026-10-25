#!/usr/bin/env python3
"""Convert a (3.1-format, uncompressed) WinHelp .HLP to a self-contained HTML page + PNG images.
usage: hlp2html.py in.hlp out.htm imgdir imgurlprefix"""
import sys, os, struct, html
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from hlp import Hlp
from hlptopic import records
from hlpcmd import split_cmds
import mrb

def esc(b):
    return html.escape(b.decode('cp1252', 'replace'), quote=False)

def fonts_css(h):
    f = h.get('|FONT')
    nf, nd, fo, do = struct.unpack_from('<HHHH', f, 0)
    fs = (do - fo) // nf
    faces = [f[fo+i*fs:fo+(i+1)*fs].split(b'\0')[0].decode('latin1') for i in range(nf)]
    css = []
    for i in range(nd):
        a, hp, fam, fi = struct.unpack_from('<BBBH', f, do + 11*i)
        fg = f[do+11*i+5:do+11*i+8]
        r = ['font-size:%gpt' % (hp / 2 if hp else 10)]
        face = faces[fi] if fi < len(faces) else 'Arial'
        r.append("font-family:'%s',Arial,Helvetica,sans-serif" % ('Arial' if face.startswith(('Univers', 'Helv', 'TKC')) else face))
        if a & 1: r.append('font-weight:bold')
        if a & 2: r.append('font-style:italic')
        dec = []
        if a & 4 or a & 0x10: dec.append('underline')
        if a & 8: dec.append('line-through')
        if dec: r.append('text-decoration:' + ' '.join(dec))
        if fg != b'\x01\x01\x00':
            r.append('color:#%02x%02x%02x' % tuple(fg))
        css.append('.f%d{%s}' % (i, ';'.join(r)))
    return '\n'.join(css)

def hotspots(bm, index=0):
    off = struct.unpack_from('<I', bm, 4 + 4*index)[0]
    p = off + 2
    for _ in range(2): _, p = mrb.culong(bm, p)
    _, p = mrb.cushort(bm, p); _, p = mrb.cushort(bm, p)
    vals = []
    for _ in range(6):
        v, p = mrb.culong(bm, p); vals.append(v)
    hs = vals[5]
    co, ho = struct.unpack_from('<II', bm, p)
    if hs == 0 or ho == 0: return []
    d = bm[off+ho: off+ho+hs]
    if d[0] != 1: return []
    n = struct.unpack_from('<H', d, 1)[0]
    macro = struct.unpack_from('<I', d, 3)[0]
    q = 7 + macro
    out = []
    for i in range(n):
        t = d[q]; x, y, w, hh = struct.unpack_from('<HHHH', d, q+3); hv = struct.unpack_from('<i', d, q+11)[0]
        out.append((t, x, y, w, hh, hv)); q += 15
    return out

def convert(path, outhtm, imgdir, imgurl):
    h = Hlp(path)
    sysd = h.get('|SYSTEM')
    title = sysd[12:].split(b'\0')[0]
    # the |SYSTEM records: first record (type 1) is the title
    rs, _ = records(h)
    ctx = h.btree('|CONTEXT', lambda b, p: (struct.unpack_from('<ii', b, p), p + 8))
    order = sorted(v for _, v in ctx)
    rank = {v: i for i, v in enumerate(order)}
    hash2topic = {hh: rank[v] for hh, v in ctx}
    os.makedirs(imgdir, exist_ok=True)
    used = set()
    names = {}
    def image(n):
        if n not in names:
            import hashlib, io
            img, _ = mrb.decode(h.get('|bm%d' % n))
            buf = io.BytesIO(); img.save(buf, 'PNG'); data = buf.getvalue()
            fn = hashlib.md5(data).hexdigest()[:10] + '.png'
            open(os.path.join(imgdir, fn), 'wb').write(data)
            names[n] = fn
        return imgurl + names[n]
    used = names
    topics = []   # [title, html]
    cur = None
    font = 0
    for r in rs:
        if r['rt'] == 2:
            cur = [r['l2'].decode('cp1252', 'replace'), []]; topics.append(cur); font = 0
            continue
        if r['rt'] != 0x20 or cur is None: continue
        strs, sols = split_cmds(r['l1'], r['l2'])
        cmds = sols[0][1]
        out = cur[1]
        span = False; pstate = {'open': False}
        def need_p():
            if not pstate['open']:
                out.append('<p>'); pstate['open'] = True
        def open_span():
            nonlocal span
            if not span:
                out.append('<span class="f%d">' % font); span = True
        def close_span():
            nonlocal span
            if span: out.append('</span>'); span = False
        for s, (c, op) in zip(strs, cmds):
            if s:
                need_p(); open_span(); out.append(esc(s))
            if c == 0xff: pass
            elif c == 0x80:
                close_span(); font = struct.unpack('<H', op)[0]
            elif c == 0x81:
                need_p(); close_span(); out.append('<br>')
            elif c == 0x82:
                close_span()
                if pstate['open']: out.append('</p>'); pstate['open'] = False
                else: out.append('<p>&nbsp;</p>') if False else None
            elif c == 0x83:
                need_p(); out.append('&emsp;')
            elif c in (0xe2, 0xe3, 0xe6, 0xe7):
                need_p(); close_span()
                hv = struct.unpack('<i', op)[0]
                t = hash2topic.get(hv)
                out.append('<a class="%s" href="#t%s">' % ('popup' if c in (0xe2, 0xe6) else 'jump', t if t is not None else 0))
            elif c == 0x89:
                close_span(); out.append('</a>')
            elif c in (0x86, 0x87, 0x88):
                need_p(); close_span()
                n = struct.unpack('<H', op[6:8])[0]
                bm = h.get('|bm%d' % n)
                hs = hotspots(bm)
                src = image(n)
                if hs:
                    mname = 'm%d' % n
                    out.append('<map name="%s">' % mname)
                    for t, x, y, w, hh, hv in hs:
                        tt = hash2topic.get(hv, 0)
                        out.append('<area shape="rect" coords="%d,%d,%d,%d" href="#t%d">' % (x, y, x+w, y+hh, tt))
                    out.append('</map>')
                    out.append('<img src="%s" usemap="#%s" alt="">' % (src, mname))
                else:
                    out.append('<img src="%s" alt="">' % src)
        close_span()
        if pstate['open']: out.append('</p>')
    topics = [t for t in topics if True]
    n_named = len(order)
    body = []
    for i, (tt, parts) in enumerate(topics[:max(n_named, 1)]):
        body.append('<section class="topic" id="t%d" data-title="%s">%s</section>' % (i, html.escape(tt), ''.join(parts)))
    doc = '''<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>%s</title>
<style>
body{margin:0;padding:12px 20px;background:#fff;color:#000;font-family:Arial,Helvetica,sans-serif;font-size:10pt;line-height:1.35}
%s
a.jump{color:#008000;text-decoration:underline}a.popup{color:#008000;text-decoration:underline dotted}
a.jump span,a.popup span{color:inherit}
p{margin:0 0 4px}img{vertical-align:middle;border:0}
section.topic{display:none}section.topic.on{display:block}
nav{border-bottom:1px solid #ccc;margin:-12px -20px 10px;padding:6px 20px;background:#f0f0f0}
</style></head><body>
<nav><a href="#t0">Contents</a></nav>
%s
<script>
function show(){var h=(location.hash||"#t0").slice(1),s=document.querySelectorAll("section.topic"),f=null;
for(var i=0;i<s.length;i++){var on=s[i].id==h;s[i].className="topic"+(on?" on":"");if(on)f=s[i];}
if(!f&&s.length){s[0].className="topic on";f=s[0];}
if(f)document.title=%s+" - "+f.getAttribute("data-title");window.scrollTo(0,0);}
window.addEventListener("hashchange",show);show();
</script></body></html>''' % (html.escape(title.decode('cp1252')), fonts_css(h), '\n'.join(body), repr(title.decode('cp1252')).replace("'", '"'))
    open(outhtm, 'w', encoding='utf-8').write(doc)
    return len(topics), len(used)

if __name__ == '__main__':
    print(convert(*sys.argv[1:5]))
