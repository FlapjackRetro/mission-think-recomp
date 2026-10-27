%define IAT_CWE 0x5197b4
%define IAT_MW 0x5196cc
%define IAT_SWP 0x51968c
%define IAT_DWP 0x5197a8
%define IAT_GCR 0x519748
%define IAT_STC 0x5196a8
%define IAT_CTS 0x5197c8
%define IAT_MWP 0x5196d8
%define IAT_BB 0x519600
%define IAT_SDIB 0x5195d4
%define IAT_IR 0x5196f8
%define IAT_SCR 0x5195a4
%define IAT_GRB 0x5195cc
%define IAT_CRR 0x519660
%define IAT_DO 0x519620

bits 32
org 0x596000
entry_table:
  jmp near screen_rect   ; +0
  jmp near cwe_shim      ; +5
  jmp near mw_shim       ; +10
  jmp near swp_shim      ; +15
  jmp near dwp_shim      ; +20
  jmp near gcr_shim      ; +25
  jmp near stc_shim      ; +30
  jmp near cts_shim      ; +35
  jmp near mwp_shim      ; +40
  jmp near bitblt_shim   ; +45
  jmp near sdib_shim     ; +50
  jmp near mouse_hook    ; +55
  jmp near raw_stc       ; +60
  jmp near invrect_shim  ; +65
  jmp near scr_shim      ; +70
  jmp near msgpt_fix     ; +75

; RECT* screen_rect(RECT* out): replaces FUN_004b0150 ("screen rect").
; Before the frame exists: outer rect of a centred fixed [g_cw] x [g_ch] window (the size picked at startup).
; Afterwards: the frame's (virtual, i.e. 640x480) client size plus its menu height.
screen_rect:
 push ebp
 mov ebp,esp
 sub esp,0x30
 push ebx
 push esi
 mov ebx,[ebp+8]
 mov eax,[0x511958]
 test eax,eax
 jz .initial
 mov eax,[eax+0x9e]
 test eax,eax
 jz .initial
 lea edx,[ebp-0x10]
 push edx
 push eax
 call 0x4d03e3          ; GetClientRect (hooked: virtual units)
 push dword [0x511958]
 lea ecx,[ebp-0x30]
 push ecx
 call 0x4ac9af
 add esp,8
 mov esi,[ebp-0x2c]
 add esi,[ebp-0x28]
 add esi,[ebp-0x24]
 add esi,[ebp-4]
 mov dword [ebx],0
 mov dword [ebx+4],0
 mov eax,[ebp-8]
 mov [ebx+8],eax
 mov [ebx+0xc],esi
 jmp .done
.initial:
 mov dword [ebp-0x10],0
 mov dword [ebp-0xc],0
 cmp dword [g_cw],0
 jne .have
 call ensure_cfg
.have:
 mov eax,[g_cw]
 mov [ebp-8],eax
 mov eax,[g_ch]
 mov [ebp-4],eax
 push 1
 push 0x02CA0000
 lea eax,[ebp-0x10]
 push eax
 call 0x4d04d3          ; AdjustWindowRect
 mov esi,[ebp-8]
 sub esi,[ebp-0x10]
 mov eax,[ebp-4]
 sub eax,[ebp-0xc]
 mov [ebp-0x20],eax
 push 0
 call 0x4d038f
 sub eax,esi
 sar eax,1
 mov [ebx],eax
 add eax,esi
 mov [ebx+8],eax
 push 1
 call 0x4d038f
 sub eax,[ebp-0x20]
 sar eax,1
 jns .ypos
 xor eax,eax
.ypos:
 mov [ebx+4],eax
 add eax,[ebp-0x20]
 mov [ebx+0xc],eax
.done:
 mov eax,ebx
 pop esi
 pop ebx
 mov esp,ebp
 pop ebp
 ret


; ---- scaling helpers: virtual = 640x480 world, real = [g_cw] x [g_ch] client pixels (cw in 640/800/1024/1280/1600) ----
; eax = round(eax * cw / 640); all other registers preserved.  The first use runs the startup size picker.
s_up:
 cmp dword [g_cw],0
 jne .ok
 call ensure_cfg
.ok:
 push edx
 push ecx
 imul eax,[g_cw]
 mov edx,eax
 sar edx,31
 mov ecx,320
 xor ecx,edx
 sub ecx,edx
 add eax,ecx
 cdq
 mov ecx,640
 idiv ecx
 pop ecx
 pop edx
 ret

; eax = eax * 640 / cw (truncated, so a pointer on the last real pixel stays inside the virtual frame)
s_dn:
 cmp dword [g_cw],0
 jne .ok
 call ensure_cfg
.ok:
 push edx
 imul eax,eax,640
 cdq
 idiv dword [g_cw]
 pop edx
 ret

; fix_xw: edx -> x, ecx -> w (dwords): x' = up(x), w' = up(x+w) - up(x), so scaled neighbours still tile exactly.
; CW_USEDEFAULT (0x80000000) values are left alone.  All registers preserved.
fix_xw:
 push eax
 push ebx
 push esi
 cmp dword [edx],0x80000000
 je .done
 cmp dword [ecx],0x80000000
 je .done
 mov eax,[edx]
 call s_up
 mov esi,eax
 mov eax,[edx]
 add eax,[ecx]
 call s_up
 sub eax,esi
 mov [ecx],eax
 mov [edx],esi
.done:
 pop esi
 pop ebx
 pop eax
 ret

; int is_child(HWND)
is_child:
 push -16
 push dword [esp+8]
 call 0x4d037d          ; GetWindowLongA(hwnd, GWL_STYLE)
 shr eax,30
 and eax,1
 ret 4

; ---- window geometry: children are created/moved in virtual (640x480) units ----
cwe_shim:                ; CreateWindowExA(ex,cls,name,style,x,y,w,h,...)
 test dword [esp+0x10],0x40000000
 jz .p
 lea edx,[esp+0x14]
 lea ecx,[esp+0x1c]
 call fix_xw
 lea edx,[esp+0x18]
 lea ecx,[esp+0x20]
 call fix_xw
.p:
 jmp [IAT_CWE]

mw_shim:                 ; MoveWindow(hwnd,x,y,w,h,repaint)
 push dword [esp+4]
 call is_child
 test eax,eax
 jz .p
 lea edx,[esp+8]
 lea ecx,[esp+0x10]
 call fix_xw
 lea edx,[esp+0xc]
 lea ecx,[esp+0x14]
 call fix_xw
.p:
 jmp [IAT_MW]

swp_shim:                ; SetWindowPos(hwnd,after,x,y,cx,cy,flags)
 push dword [esp+4]
 call is_child
 test eax,eax
 jz .p
 lea edx,[esp+0xc]
 lea ecx,[esp+0x14]
 call fix_xw
 lea edx,[esp+0x10]
 lea ecx,[esp+0x18]
 call fix_xw
.p:
 jmp [IAT_SWP]

dwp_shim:                ; DeferWindowPos(hdwp,hwnd,after,x,y,cx,cy,flags)
 push dword [esp+8]
 call is_child
 test eax,eax
 jz .p
 lea edx,[esp+0x10]
 lea ecx,[esp+0x18]
 call fix_xw
 lea edx,[esp+0x14]
 lea ecx,[esp+0x1c]
 call fix_xw
.p:
 jmp [IAT_DWP]

; ---- client coordinates are virtual (real * 640 / cw) ----
gcr_shim:                ; GetClientRect(hwnd, rect)
 push dword [esp+8]
 push dword [esp+8]
 call [IAT_GCR]
 test eax,eax
 jz .r
 mov ecx,[esp+8]
 mov eax,[ecx+8]
 call s_dn
 mov [ecx+8],eax
 mov eax,[ecx+0xc]
 call s_dn
 mov [ecx+0xc],eax
 mov eax,1
.r:
 ret 8

stc_shim:                ; ScreenToClient(hwnd, pt)
 push dword [esp+8]
 push dword [esp+8]
 call [IAT_STC]
 test eax,eax
 jz .r
 mov ecx,[esp+8]
 mov eax,[ecx]
 call s_dn
 mov [ecx],eax
 mov eax,[ecx+4]
 call s_dn
 mov [ecx+4],eax
 mov eax,1
.r:
 ret 8

raw_stc:
 jmp [IAT_STC]

cts_shim:                ; ClientToScreen(hwnd, pt)
 mov ecx,[esp+8]
 mov eax,[ecx]
 call s_up
 mov [ecx],eax
 mov eax,[ecx+4]
 call s_up
 mov [ecx+4],eax
 jmp [IAT_CTS]

mwp_shim:                ; MapWindowPoints(from,to,pts,n)
 cmp dword [esp+4],0
 je .noin
 mov ecx,[esp+0x10]
 mov edx,[esp+0xc]
.l1:
 test ecx,ecx
 jz .noin
 mov eax,[edx]
 call s_up
 mov [edx],eax
 mov eax,[edx+4]
 call s_up
 mov [edx+4],eax
 add edx,8
 dec ecx
 jmp .l1
.noin:
 push dword [esp+0x10]
 push dword [esp+0x10]
 push dword [esp+0x10]
 push dword [esp+0x10]
 call [IAT_MWP]
 push eax
 cmp dword [esp+0xc],0
 je .done
 mov ecx,[esp+0x14]
 mov edx,[esp+0x10]
.l2:
 test ecx,ecx
 jz .done
 mov eax,[edx]
 call s_dn
 mov [edx],eax
 mov eax,[edx+4]
 call s_dn
 mov [edx+4],eax
 add edx,8
 dec ecx
 jmp .l2
.done:
 pop eax
 ret 0x10

; ---- drawing: blits aimed at a window DC are stretched to the real client size ----
init_gdi:
 cmp dword [pStretchBlt],0
 jne .r
 push ebx
 push s_gdi
 call 0x4d0059
 mov ebx,eax
 push s_sbm
 push ebx
 call 0x4cffc3
 mov [pSetStretchBltMode],eax
 push s_grd
 push ebx
 call 0x4cffc3
 mov [pGetRegionData],eax
 push s_ecr
 push ebx
 call 0x4cffc3
 mov [pExtCreateRegion],eax
 push s_user
 call 0x4d0059
 push s_wfd
 push eax
 call 0x4cffc3
 mov [pWindowFromDC],eax
 push s_sb
 push ebx
 call 0x4cffc3
 mov [pStretchBlt],eax
 pop ebx
.r:
 ret

; int is_window_dc(HDC)
is_window_dc:
 call init_gdi
 push dword [esp+4]
 call [pWindowFromDC]
 neg eax
 sbb eax,eax
 neg eax
 ret 4

%macro CALCDEST 0
 mov eax,[ebp+0xc]
 call s_up
 mov ebx,eax
 mov eax,[ebp+0xc]
 add eax,[ebp+0x14]
 call s_up
 sub eax,ebx
 mov [ebp-0x10],eax
 mov eax,[ebp+0x10]
 call s_up
 mov [ebp-0xc],eax
 mov eax,[ebp+0x10]
 add eax,[ebp+0x18]
 call s_up
 sub eax,[ebp-0xc]
 mov [ebp-8],eax
 push 3
 push dword [ebp+8]
 call [pSetStretchBltMode]
%endmacro

bitblt_shim:
 push ebp
 mov ebp,esp
 sub esp,0x20
 push ebx
 push dword [ebp+8]
 call is_window_dc
 test eax,eax
 jz .pass
 CALCDEST
 push dword [ebp+0x28]
 push dword [ebp+0x18]
 push dword [ebp+0x14]
 push dword [ebp+0x24]
 push dword [ebp+0x20]
 push dword [ebp+0x1c]
 push dword [ebp-8]
 push dword [ebp-0x10]
 push dword [ebp-0xc]
 push ebx
 push dword [ebp+8]
 call [pStretchBlt]
 pop ebx
 mov esp,ebp
 pop ebp
 ret 0x24
.pass:
 pop ebx
 mov esp,ebp
 pop ebp
 jmp [IAT_BB]

sdib_shim:
 push ebp
 mov ebp,esp
 sub esp,0x20
 push ebx
 push dword [ebp+8]
 call is_window_dc
 test eax,eax
 jz .pass
 CALCDEST
 push dword [ebp+0x38]
 push dword [ebp+0x34]
 push dword [ebp+0x30]
 push dword [ebp+0x2c]
 push dword [ebp+0x28]
 push dword [ebp+0x24]
 push dword [ebp+0x20]
 push dword [ebp+0x1c]
 push dword [ebp-8]
 push dword [ebp-0x10]
 push dword [ebp-0xc]
 push ebx
 push dword [ebp+8]
 call [IAT_SDIB]
 pop ebx
 mov esp,ebp
 pop ebp
 ret 0x34
.pass:
 pop ebx
 mov esp,ebp
 pop ebp
 jmp [IAT_SDIB]

; ---- invalidation / clipping: rects and regions the game hands to USER/GDI are virtual (640x480) ----
; InvalidateRect(hwnd, RECT*, erase): scale the rect to real pixels (copy, the caller's RECT is untouched).
; Without this, e.g. the client rect from the (virtual) GetClientRect only invalidates the top-left 640x480.
invrect_shim:
 push ebp
 mov ebp,esp
 sub esp,0x10
 push ebx
 mov ebx,[ebp+0xc]
 test ebx,ebx
 jz .p
 mov eax,[ebx]
 call s_up
 mov [ebp-0x10],eax
 mov eax,[ebx+4]
 call s_up
 mov [ebp-0xc],eax
 mov eax,[ebx+8]
 call s_up
 mov [ebp-8],eax
 mov eax,[ebx+0xc]
 call s_up
 mov [ebp-4],eax
 push dword [ebp+0x10]
 lea eax,[ebp-0x10]
 push eax
 push dword [ebp+8]
 call [IAT_IR]
 pop ebx
 mov esp,ebp
 pop ebp
 ret 12
.p:
 pop ebx
 mov esp,ebp
 pop ebp
 jmp [IAT_IR]

; SelectClipRgn(hdc, hrgn): the engine clips its window blits to a region in virtual units
; (e.g. 0,0,640,480 for a full repaint).  On a window DC that region must be scaled to real pixels,
; otherwise the stretched blit is cropped to the top-left 640x480 (this was the "splash only
; draws unscaled in the corner" bug).  Regions on memory DCs are left alone.
scr_shim:
 push ebp
 mov ebp,esp
 push ebx
 push esi
 push edi
 sub esp,0x10
 cmp dword [ebp+0xc],0
 je .pass
 push dword [ebp+8]
 call is_window_dc
 test eax,eax
 jz .pass
 sub esp,0xE00
 mov edi,esp
 push edi
 push 0xE00
 push dword [ebp+0xc]
 call [pGetRegionData]
 test eax,eax
 jz .big
 mov ebx,eax
 mov eax,[edi+0x10]
 call s_up
 mov [edi+0x10],eax
 mov eax,[edi+0x14]
 call s_up
 mov [edi+0x14],eax
 mov eax,[edi+0x18]
 call s_up
 mov [edi+0x18],eax
 mov eax,[edi+0x1c]
 call s_up
 mov [edi+0x1c],eax
 mov ecx,[edi+8]
 lea edx,[edi+0x20]
.l:
 test ecx,ecx
 jz .mk
 mov eax,[edx]
 call s_up
 mov [edx],eax
 mov eax,[edx+4]
 call s_up
 mov [edx+4],eax
 mov eax,[edx+8]
 call s_up
 mov [edx+8],eax
 mov eax,[edx+12]
 call s_up
 mov [edx+12],eax
 add edx,16
 dec ecx
 jmp .l
.mk:
 push edi
 push ebx
 push 0
 call [pExtCreateRegion]
 jmp .have
.big:                    ; region too complex for the stack buffer: use its scaled bounding box
 lea esi,[ebp-0x1c]
 push esi
 push dword [ebp+0xc]
 call [IAT_GRB]
 mov eax,[esi+12]
 call s_up
 push eax
 mov eax,[esi+8]
 call s_up
 push eax
 mov eax,[esi+4]
 call s_up
 push eax
 mov eax,[esi]
 call s_up
 push eax
 call [IAT_CRR]
.have:
 test eax,eax
 jz .pass
 mov esi,eax
 push esi
 push dword [ebp+8]
 call [IAT_SCR]
 mov ebx,eax
 push esi
 call [IAT_DO]
 mov eax,ebx
 lea esp,[ebp-0xc]
 pop edi
 pop esi
 pop ebx
 pop ebp
 ret 8
.pass:
 lea esp,[ebp-0xc]
 pop edi
 pop esi
 pop ebx
 pop ebp
 jmp [IAT_SCR]

; FUN_004b1762 is the hit-test code's mouse-position getter: it reads x/y from lParam of the engine's copy of the
; current message (0x513338), which is the pump's raw window-pixel lParam (mouse_hook only fixes the
; lParam handed to the child proc).  Hooked at VA 0x4b17a1 (the two movswl + two stores to the POINT at [ebp-8]):
; scale x/y down to virtual there.   in: ecx = y (word), edx = x (word)
msgpt_fix:
 push eax
 movsx eax,cx
 call s_dn
 mov [ebp-4],eax
 movsx eax,dx
 call s_dn
 mov [ebp-8],eax
 pop eax
 jmp 0x4b17ad

; ---- mouse messages: window coords -> virtual ----
mouse_hook:
 push ebp
 mov ebp,esp
 mov eax,[ebp+0xc]
 sub eax,0x200
 cmp eax,9
 ja .d
 movsx eax,word [ebp+0x16]
 call s_dn
 shl eax,16
 mov ecx,eax
 movsx eax,word [ebp+0x14]
 call s_dn
 movzx eax,ax
 or eax,ecx
 mov [ebp+0x14],eax
.d:
 pop ebp
 push ebp
 mov ebp,esp
 add esp,0xffffff3c
 jmp 0x4b46aa

; ---- startup display-size picker ----
; Shown once, the first time the scale is needed (i.e. while the frame is being sized, before any window exists).
; Radio list of 640x480 / 800x600 / 1024x768 / 1280x960 / 1600x1200; the choice is stored in tlc.ini
; ([Display] Width=...) and preselected next time.  [Display] Ask=0 in tlc.ini skips the dialog and uses Width.
ensure_cfg:
 pushad
 mov dword [g_cw],1280     ; sane value should anything re-enter before we are done
 mov dword [g_ch],960
 push s_k32
 call 0x4d0059
 mov ebx,eax
 mov esi,tab_k32
 call resolve_tab
 push s_user
 call 0x4d0059
 mov ebx,eax
 mov esi,tab_user
 call resolve_tab
 push cfg_path
 push 1280
 push s_width
 push s_display
 call [pGPPI]
 mov dword [sel],3
 xor ecx,ecx
.f:
 cmp ecx,5
 jae .got
 cmp eax,[widths+ecx*4]
 jne .n
 mov [sel],ecx
.n:
 inc ecx
 jmp .f
.got:
 push cfg_path
 push 1
 push s_ask
 push s_display
 call [pGPPI]
 test eax,eax
 jz .apply
 push 0
 push dlgproc
 push 0
 push dlgtemplate
 push 0x400000
 call [pDialogBox]
 test eax,eax
 jle .apply              ; closed/cancelled: use the default, do not save
 dec eax
 mov [sel],eax
 push cfg_path
 push dword [strs+eax*4]
 push s_width
 push s_display
 call [pWPPS]
.apply:
 mov eax,[sel]
 mov eax,[widths+eax*4]
 mov [g_cw],eax
 lea eax,[eax+eax*2]
 shr eax,2
 mov [g_ch],eax
 popad
 ret

resolve_tab:             ; esi -> {name, &dest}... 0-terminated, ebx = module
.l:
 mov eax,[esi]
 test eax,eax
 jz .r
 push eax
 push ebx
 call 0x4cffc3
 mov edi,[esi+4]
 mov [edi],eax
 add esi,8
 jmp .l
.r:
 ret

dlgproc:                 ; BOOL CALLBACK (hdlg, msg, wparam, lparam)
 mov eax,[esp+8]
 cmp eax,0x110           ; WM_INITDIALOG
 je .init
 cmp eax,0x111           ; WM_COMMAND
 je .cmd
 xor eax,eax
 ret 16
.init:
 push ebx
 mov ebx,[esp+8]
 mov eax,[sel]
 add eax,101
 push eax
 push 105
 push 101
 push ebx
 call [pCheckRadio]
 mov eax,[sel]
 add eax,101
 push eax
 push ebx
 call [pGetDlgItem]
 push eax
 call [pSetFocus]
 pop ebx
 xor eax,eax             ; focus already set
 ret 16
.cmd:
 movzx eax,word [esp+0xc]
 cmp eax,1
 je .ok
 cmp eax,2
 je .cancel
 xor eax,eax
 ret 16
.cancel:
 push 0
 push dword [esp+8]
 call [pEndDialog]
 mov eax,1
 ret 16
.ok:
 push ebx
 push esi
 mov ebx,[esp+0xc]
 xor esi,esi
.l:
 lea eax,[esi+101]
 push eax
 push ebx
 call [pIsChecked]
 test eax,eax
 jnz .found
 inc esi
 cmp esi,5
 jb .l
 mov esi,[sel]
.found:
 lea eax,[esi+1]
 push eax
 push ebx
 call [pEndDialog]
 pop esi
 pop ebx
 mov eax,1
 ret 16

%macro ITEM 7            ; style, x, y, cx, cy, id, class  (text follows as db)
 dd %1
 dd 0
 dw %2, %3, %4, %5, %6
 dw 0xFFFF, %7
%endmacro

align 4, db 0
dlgtemplate:
 dd 0x80C80AC0           ; POPUP|CAPTION|SYSMENU|MODALFRAME|SETFONT|CENTER|SETFOREGROUND
 dd 0
 dw 7
 dw 0, 0, 160, 112
 dw 0, 0
 db __utf16__("Mission T.H.I.N.K. - Display Size"), 0, 0
 dw 8
 db __utf16__("MS Shell Dlg"), 0, 0
 align 4, db 0
 ITEM 0x50000000, 10, 8, 140, 10, 0xFFFF, 0x0082
 db __utf16__("Choose the window size:"), 0, 0
 dw 0
 align 4, db 0
 ITEM 0x50030009, 16, 24, 130, 12, 101, 0x0080
 db __utf16__("640 x 480  (1x)"), 0, 0
 dw 0
 align 4, db 0
 ITEM 0x50010009, 16, 38, 130, 12, 102, 0x0080
 db __utf16__("800 x 600  (1.25x)"), 0, 0
 dw 0
 align 4, db 0
 ITEM 0x50010009, 16, 52, 130, 12, 103, 0x0080
 db __utf16__("1024 x 768  (1.6x)"), 0, 0
 dw 0
 align 4, db 0
 ITEM 0x50010009, 16, 66, 130, 12, 104, 0x0080
 db __utf16__("1280 x 960  (2x)"), 0, 0
 dw 0
 align 4, db 0
 ITEM 0x50010009, 16, 80, 130, 12, 105, 0x0080
 db __utf16__("1600 x 1200  (2.5x)"), 0, 0
 dw 0
 align 4, db 0
 ITEM 0x50010001, 60, 95, 40, 14, 1, 0x0080
 db __utf16__("Start"), 0, 0
 dw 0
 align 4, db 0

g_cw dd 0                  ; real client size; 0 = not chosen yet
g_ch dd 0
sel dd 3
widths dd 640, 800, 1024, 1280, 1600
strs dd s_w0, s_w1, s_w2, s_w3, s_w4
s_w0 db '640',0
s_w1 db '800',0
s_w2 db '1024',0
s_w3 db '1280',0
s_w4 db '1600',0
cfg_path db '.\tlc.ini',0
s_display db 'Display',0
s_width db 'Width',0
s_ask db 'Ask',0
s_k32 db 'kernel32.dll',0
pGPPI dd 0
pWPPS dd 0
pDialogBox dd 0
pEndDialog dd 0
pCheckRadio dd 0
pIsChecked dd 0
pGetDlgItem dd 0
pSetFocus dd 0
n_gpp db 'GetPrivateProfileIntA',0
n_wpp db 'WritePrivateProfileStringA',0
n_dbi db 'DialogBoxIndirectParamA',0
n_end db 'EndDialog',0
n_crb db 'CheckRadioButton',0
n_idc db 'IsDlgButtonChecked',0
n_gdi db 'GetDlgItem',0
n_sf db 'SetFocus',0
tab_k32 dd n_gpp, pGPPI, n_wpp, pWPPS, 0
tab_user dd n_dbi, pDialogBox, n_end, pEndDialog, n_crb, pCheckRadio, n_idc, pIsChecked, n_gdi, pGetDlgItem, n_sf, pSetFocus, 0

pStretchBlt dd 0
pSetStretchBltMode dd 0
pWindowFromDC dd 0
pGetRegionData dd 0
pExtCreateRegion dd 0
s_gdi db 'gdi32.dll',0
s_user db 'user32.dll',0
s_sb db 'StretchBlt',0
s_sbm db 'SetStretchBltMode',0
s_wfd db 'WindowFromDC',0
s_grd db 'GetRegionData',0
s_ecr db 'ExtCreateRegion',0
