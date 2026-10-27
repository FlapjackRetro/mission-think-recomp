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
%define F 2
%define CLIENT_W 1280
%define CLIENT_H 960
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
; Before the frame exists: outer rect of a centred fixed CLIENT_W x CLIENT_H window.
; Afterwards: the frame's (virtual, i.e. 1/F scaled) client size plus its menu height.
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
 mov dword [ebp-8],CLIENT_W
 mov dword [ebp-4],CLIENT_H
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

; int is_child(HWND)
is_child:
 push -16
 push dword [esp+8]
 call 0x4d037d          ; GetWindowLongA(hwnd, GWL_STYLE)
 shr eax,30
 and eax,1
 ret 4

; ---- window geometry: children are created/moved in virtual (1/F) units ----
cwe_shim:                ; CreateWindowExA(ex,cls,name,style,x,y,w,h,...)
 test dword [esp+0x10],0x40000000
 jz .p
 cmp dword [esp+0x14],0x80000000
 je .a
 shl dword [esp+0x14],1
.a:
 cmp dword [esp+0x18],0x80000000
 je .b
 shl dword [esp+0x18],1
.b:
 cmp dword [esp+0x1c],0x80000000
 je .c
 shl dword [esp+0x1c],1
.c:
 cmp dword [esp+0x20],0x80000000
 je .p
 shl dword [esp+0x20],1
.p:
 jmp [IAT_CWE]

mw_shim:                 ; MoveWindow(hwnd,x,y,w,h,repaint)
 push dword [esp+4]
 call is_child
 test eax,eax
 jz .p
 shl dword [esp+8],1
 shl dword [esp+0xc],1
 shl dword [esp+0x10],1
 shl dword [esp+0x14],1
.p:
 jmp [IAT_MW]

swp_shim:                ; SetWindowPos(hwnd,after,x,y,cx,cy,flags)
 push dword [esp+4]
 call is_child
 test eax,eax
 jz .p
 shl dword [esp+0xc],1
 shl dword [esp+0x10],1
 shl dword [esp+0x14],1
 shl dword [esp+0x18],1
.p:
 jmp [IAT_SWP]

dwp_shim:                ; DeferWindowPos(hdwp,hwnd,after,x,y,cx,cy,flags)
 push dword [esp+8]
 call is_child
 test eax,eax
 jz .p
 shl dword [esp+0x10],1
 shl dword [esp+0x14],1
 shl dword [esp+0x18],1
 shl dword [esp+0x1c],1
.p:
 jmp [IAT_DWP]

; ---- client coordinates are virtual (real / F) ----
gcr_shim:                ; GetClientRect(hwnd, rect)
 push dword [esp+8]
 push dword [esp+8]
 call [IAT_GCR]
 test eax,eax
 jz .r
 mov ecx,[esp+8]
 sar dword [ecx+8],1
 sar dword [ecx+0xc],1
.r:
 ret 8

stc_shim:                ; ScreenToClient(hwnd, pt)
 push dword [esp+8]
 push dword [esp+8]
 call [IAT_STC]
 test eax,eax
 jz .r
 mov ecx,[esp+8]
 sar dword [ecx],1
 sar dword [ecx+4],1
.r:
 ret 8

raw_stc:
 jmp [IAT_STC]

cts_shim:                ; ClientToScreen(hwnd, pt)
 mov ecx,[esp+8]
 shl dword [ecx],1
 shl dword [ecx+4],1
 jmp [IAT_CTS]

mwp_shim:                ; MapWindowPoints(from,to,pts,n)
 cmp dword [esp+4],0
 je .noin
 mov ecx,[esp+0x10]
 mov edx,[esp+0xc]
.l1:
 test ecx,ecx
 jz .noin
 shl dword [edx],1
 shl dword [edx+4],1
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
 sar dword [edx],1
 sar dword [edx+4],1
 add edx,8
 dec ecx
 jmp .l2
.done:
 pop eax
 ret 0x10

; ---- drawing: blits aimed at a window DC are stretched by F ----
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
 mov ebx,[ebp+0xc]
 shl ebx,1
 mov eax,[ebp+0x10]
 shl eax,1
 mov [ebp-0xc],eax
 mov eax,[ebp+0x14]
 shl eax,1
 mov [ebp-0x10],eax
 mov eax,[ebp+0x18]
 shl eax,1
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

; ---- invalidation / clipping: rects and regions the game hands to USER/GDI are virtual (1/F) ----
; InvalidateRect(hwnd, RECT*, erase): scale the rect to real pixels (copy, the caller's RECT is untouched).
; Without this, e.g. the client rect from the (virtual) GetClientRect only invalidates the top-left 640x480.
invrect_shim:
 push ebp
 mov ebp,esp
 sub esp,0x10
 mov eax,[ebp+0xc]
 test eax,eax
 jz .p
 mov ecx,[eax]
 add ecx,ecx
 mov [ebp-0x10],ecx
 mov ecx,[eax+4]
 add ecx,ecx
 mov [ebp-0xc],ecx
 mov ecx,[eax+8]
 add ecx,ecx
 mov [ebp-8],ecx
 mov ecx,[eax+0xc]
 add ecx,ecx
 mov [ebp-4],ecx
 push dword [ebp+0x10]
 lea eax,[ebp-0x10]
 push eax
 push dword [ebp+8]
 call [IAT_IR]
 mov esp,ebp
 pop ebp
 ret 12
.p:
 mov esp,ebp
 pop ebp
 jmp [IAT_IR]

; SelectClipRgn(hdc, hrgn): the engine clips its window blits to a region in virtual units
; (e.g. 0,0,640,480 for a full repaint).  On a window DC that region must be scaled to real pixels,
; otherwise the 2x-stretched blit is cropped to the top-left 640x480 (this was the "splash only
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
 shl dword [edi+0x10],1
 shl dword [edi+0x14],1
 shl dword [edi+0x18],1
 shl dword [edi+0x1c],1
 mov ecx,[edi+8]
 lea edx,[edi+0x20]
.l:
 test ecx,ecx
 jz .mk
 shl dword [edx],1
 shl dword [edx+4],1
 shl dword [edx+8],1
 shl dword [edx+12],1
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
 add eax,eax
 push eax
 mov eax,[esi+8]
 add eax,eax
 push eax
 mov eax,[esi+4]
 add eax,eax
 push eax
 mov eax,[esi]
 add eax,eax
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
; current message (0x513338), which is the pump's raw, unhalved window-pixel lParam (mouse_hook only fixes the
; lParam handed to the child proc).  Hooked at VA 0x4b17a1 (the two movswl + two stores to the POINT at [ebp-8]):
; halve x/y there.   in: ecx = y (word), edx = x (word)
msgpt_fix:
 movsx ecx,cx
 sar ecx,1
 movsx edx,dx
 sar edx,1
 mov [ebp-8],edx
 mov [ebp-4],ecx
 jmp 0x4b17ad

; ---- mouse messages: window coords -> virtual ----
mouse_hook:
 push ebp
 mov ebp,esp
 mov eax,[ebp+0xc]
 sub eax,0x200
 cmp eax,9
 ja .d
 movsx eax,word [ebp+0x14]
 sar eax,1
 movzx eax,ax
 movsx ecx,word [ebp+0x16]
 sar ecx,1
 shl ecx,16
 or eax,ecx
 mov [ebp+0x14],eax
.d:
 pop ebp
 push ebp
 mov ebp,esp
 add esp,0xffffff3c
 jmp 0x4b46aa

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
