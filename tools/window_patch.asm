bits 32
org 0x596000
; RECT* screen_rect(RECT* out)  -- replaces FUN_004b0150's "screen size" with the frame's size
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
 call 0x424354
.out:
 jmp 0x4ae272
