bits 32
org 0x4d0568
; stdcall BOOL WinHelpA(HWND hwnd, LPCSTR file, UINT cmd, DWORD data)
; Replaces the (unsupported on Win10/11) WinHelp call: rewrites "<name>.hlp" to "<name>.htm" in place
; and opens it with ShellExecuteA.
shim:
    push ebp
    mov  ebp, esp
    cmp  dword [ebp+16], 2        ; HELP_QUIT
    je   .done
    mov  ecx, [ebp+12]            ; file
.len:
    cmp  byte [ecx], 0
    je   .end
    inc  ecx
    jmp  short .len
.end:
    cmp  byte [ecx-1], 'p'
    jne  .go
    cmp  byte [ecx-2], 'l'
    jne  .go
    cmp  byte [ecx-3], 'h'
    jne  .go
    mov  byte [ecx-2], 't'
    mov  byte [ecx-1], 'm'
.go:
    push str_shell32
    call 0x4cffe7                 ; LoadLibraryA
    test eax, eax
    jz   .done
    push str_shellexec
    push eax
    call 0x4cffc3                 ; GetProcAddress
    test eax, eax
    jz   .done
    push 1                        ; SW_SHOWNORMAL
    push 0                        ; lpDirectory
    push 0                        ; lpParameters
    push dword [ebp+12]           ; lpFile
    push 0                        ; lpOperation (default verb)
    push dword [ebp+8]            ; hwnd
    call eax                      ; ShellExecuteA
.done:
    mov  eax, 1
    pop  ebp
    ret  16
str_shell32:   db 'shell32', 0
str_shellexec: db 'ShellExecuteA', 0
