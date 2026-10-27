bits 32
org 0x596000
; RECT* screen_rect(RECT* out)  -- replaces FUN_004b0150's "screen size" with the frame's size
entry_table:
  jmp near screen_rect   ; +0
  jmp near wm_size       ; +5
  jmp near bitblt_shim   ; +10
  jmp near sdib_shim     ; +15
  jmp near mouse_hook    ; +20
  jmp near stc_scaled    ; +25
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
 call 0x4d03e3          ; GetClientRect(hwnd,&r)
 push dword [0x511958]
 lea ecx,[ebp-0x30]
 push ecx
 call 0x4ac9af          ; non-client/menu metrics
 add esp,8
 mov esi,[ebp-0x2c]
 add esi,[ebp-0x28]
 add esi,[ebp-0x24]
 add esi,[ebp-4]        ; + client height
 mov dword [ebx],0
 mov dword [ebx+4],0
 mov eax,[ebp-8]
 mov [ebx+8],eax
 mov [ebx+0xc],esi
 jmp .done
.initial:
 mov dword [ebp-0x10],0
 mov dword [ebp-0xc],0
 mov dword [ebp-8],640
 mov dword [ebp-4],480
 push 1
 push 0x02CF0000
 lea eax,[ebp-0x10]
 push eax
 call 0x4d04d3          ; AdjustWindowRect
 mov esi,[ebp-8]
 sub esi,[ebp-0x10]     ; w
 mov eax,[ebp-4]
 sub eax,[ebp-0xc]      ; h
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
; WM_SIZE tail: recenter stage when both frame and stage exist
wm_size:
 cmp dword [0x511958],0
 je .out
 cmp dword [0x513150],0
 je .out
 call fit_stage
.out:
 jmp 0x4ae272

; letterbox the stage (4:3) inside the frame client area
fit_stage:
 push ebp
 mov ebp,esp
 sub esp,0x20
 push ebx
 mov eax,[0x511958]
 mov eax,[eax+0x9e]
 test eax,eax
 jz .fo
 lea edx,[ebp-0x10]
 push edx
 push eax
 call 0x4d03e3
 mov eax,[ebp-8]       ; W
 mov ecx,[ebp-4]       ; H
 test eax,eax
 jle .fo
 test ecx,ecx
 jle .fo
 mov [ebp-0x18],eax
 mov [ebp-0x14],ecx
 lea edx,[eax+eax*2]
 shr edx,2             ; ch = W*3/4
 mov ebx,eax           ; cw = W
 cmp edx,ecx
 jle .fit
 mov edx,ecx           ; ch = H
 lea ebx,[ecx*4]
 mov eax,ebx
 xor edx,edx
 mov ebx,3
 div ebx               ; eax = H*4/3
 mov ebx,eax           ; cw
 mov edx,ecx           ; ch
.fit:
 mov [ebp-0x20],ebx    ; cw
 mov [ebp-0x1c],edx    ; ch
 mov eax,[0x513150]
 mov eax,[eax+0x80]
 test eax,eax
 jz .fo
 mov ebx,eax           ; stage hwnd
 mov eax,[ebp-0x14]
 sub eax,[ebp-0x1c]
 sar eax,1
 mov ecx,[ebp-0x18]
 sub ecx,[ebp-0x20]
 sar ecx,1
 push 0x14
 push dword [ebp-0x1c]
 push dword [ebp-0x20]
 push eax
 push ecx
 push 0
 push ebx
 call 0x4d02c9         ; SetWindowPos
 push 0
 push 0
 push ebx
 call 0x4d036b         ; InvalidateRect(stage, NULL, FALSE)
.fo:
 pop ebx
 mov esp,ebp
 pop ebp
 ret

; ---------------- scaling support ----------------
init_gdi:
 cmp dword [pStretchBlt],0
 jne .r
 push s_gdi
 call 0x4d0059
 push eax
 push s_sbm
 push eax
 call 0x4cffc3
 mov [pSetStretchBltMode],eax
 pop eax
 push s_sb
 push eax
 call 0x4cffc3
 mov [pStretchBlt],eax
 push s_user
 call 0x4d0059
 push s_wfd
 push eax
 call 0x4cffc3
 mov [pWindowFromDC],eax
.r:
 ret

; int stage_size(HDC, int out[2]) -> 1 if hdc is the stage window's DC and it is not 640x480
stage_size:
 push ebp
 mov ebp,esp
 sub esp,0x10
 push ebx
 call init_gdi
 mov eax,[0x513150]
 test eax,eax
 jz .no
 mov ebx,[eax+0x80]
 test ebx,ebx
 jz .no
 push dword [ebp+8]
 call [pWindowFromDC]
 cmp eax,ebx
 jne .no
 lea edx,[ebp-0x10]
 push edx
 push ebx
 call 0x4d03e3
 mov eax,[ebp-8]
 mov ecx,[ebp-4]
 test eax,eax
 jle .no
 test ecx,ecx
 jle .no
 cmp eax,640
 jne .yes
 cmp ecx,480
 je .no
.yes:
 mov edx,[ebp+0xc]
 mov [edx],eax
 mov [edx+4],ecx
 mov eax,1
 jmp .ret
.no:
 xor eax,eax
.ret:
 pop ebx
 mov esp,ebp
 pop ebp
 ret 8

; dest rect scaling: inputs [ebp+0xc..0x18]=x,y,w,h ; W=[ebp-0x18] H=[ebp-0x14] ; outputs ebx=x0, [ebp-0xc]=y0, [ebp-0x10]=wd, [ebp-8]=hd
%macro CALCDEST 0
 mov esi,[ebp-0x18]
 mov edi,[ebp-0x14]
 mov ecx,640
 mov eax,[ebp+0xc]
 imul eax,esi
 cdq
 idiv ecx
 mov ebx,eax
 mov eax,[ebp+0xc]
 add eax,[ebp+0x14]
 imul eax,esi
 add eax,639
 cdq
 idiv ecx
 sub eax,ebx
 mov [ebp-0x10],eax
 mov ecx,480
 mov eax,[ebp+0x10]
 imul eax,edi
 cdq
 idiv ecx
 mov [ebp-0xc],eax
 mov eax,[ebp+0x10]
 add eax,[ebp+0x18]
 imul eax,edi
 add eax,479
 cdq
 idiv ecx
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
 push esi
 push edi
 lea eax,[ebp-0x18]
 push eax
 push dword [ebp+8]
 call stage_size
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
 pop edi
 pop esi
 pop ebx
 mov esp,ebp
 pop ebp
 ret 0x24
.pass:
 pop edi
 pop esi
 pop ebx
 mov esp,ebp
 pop ebp
 jmp [0x519600]

sdib_shim:
 push ebp
 mov ebp,esp
 sub esp,0x20
 push ebx
 push esi
 push edi
 lea eax,[ebp-0x18]
 push eax
 push dword [ebp+8]
 call stage_size
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
 call [0x5195d4]
 pop edi
 pop esi
 pop ebx
 mov esp,ebp
 pop ebp
 ret 0x34
.pass:
 pop edi
 pop esi
 pop ebx
 mov esp,ebp
 pop ebp
 jmp [0x5195d4]

; ---------------- mouse mapping ----------------
; void scale_pt(HWND, POINT*) : window client coords -> 640x480 game coords, only for the stage window
scale_pt:
 push ebp
 mov ebp,esp
 sub esp,0x10
 push ebx
 mov eax,[0x513150]
 test eax,eax
 jz .o
 mov eax,[eax+0x80]
 cmp eax,[ebp+8]
 jne .o
 lea edx,[ebp-0x10]
 push edx
 push eax
 call 0x4d03e3
 mov ebx,[ebp+0xc]
 mov ecx,[ebp-8]
 test ecx,ecx
 jle .o
 cmp dword [ebp-4],0
 jle .o
 mov eax,[ebx]
 imul eax,640
 cdq
 idiv ecx
 mov [ebx],eax
 mov ecx,[ebp-4]
 mov eax,[ebx+4]
 imul eax,480
 cdq
 idiv ecx
 mov [ebx+4],eax
.o:
 pop ebx
 mov esp,ebp
 pop ebp
 ret 8

mouse_hook:
 push ebp
 mov ebp,esp
 sub esp,8
 mov eax,[ebp+0xc]
 sub eax,0x200
 cmp eax,9
 ja .d
 movsx eax,word [ebp+0x14]
 mov [ebp-8],eax
 movsx eax,word [ebp+0x16]
 mov [ebp-4],eax
 lea eax,[ebp-8]
 push eax
 push dword [ebp+8]
 call scale_pt
 movzx eax,word [ebp-8]
 movzx ecx,word [ebp-4]
 shl ecx,16
 or eax,ecx
 mov [ebp+0x14],eax
.d:
 mov esp,ebp
 pop ebp
 push ebp
 mov ebp,esp
 add esp,0xffffff3c
 jmp 0x4b46aa

stc_scaled:
 push dword [esp+8]
 push dword [esp+8]
 call 0x4d02f3
 push dword [esp+8]
 push dword [esp+8]
 call scale_pt
 mov eax,1
 ret 8

pStretchBlt dd 0
pSetStretchBltMode dd 0
pWindowFromDC dd 0
s_gdi db 'gdi32.dll',0
s_user db 'user32.dll',0
s_sb db 'StretchBlt',0
s_sbm db 'SetStretchBltMode',0
s_wfd db 'WindowFromDC',0
