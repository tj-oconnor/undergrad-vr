# Vulnerability Research Course Materials

## About

The following repository contains the containers, labs, and code used in our undergraduate vulnerability research course described in our **[SIGCSE 2024 paper](paper/sigcse24oconnor.pdf)**

**Please cite using:** TJ OConnor, Alex Schmith, Chris Stricklan, Marco Carvalho, Sneha Sudhakaran. *Pwn Lessons Made Easy With Docker: Toward an Undergraduate Vulnerability Research Cybersecurity Class.* Special Interest Group on Computer Science Education (SIGCSE 24), Portland, OR, March 2024 [[bib]](https://raw.githubusercontent.com/tj-oconnor/Publications/main/bib/sigcse24oconnor.bib) [[pdf]](paper/sigcse24oconnor.pdf)

## Course Virtualization Using [Docker](https://www.docker.com)

### Course Docker Container

For our class, we standardized the student environment by providing a Docker container with all the appropriate course tools and class demonstrations. These challenges are patched with the appropriate libc versions and the scripts and verified to work for the course image. You can pull the course image from dockerhub using ``docker pull tjoconnor/undergrad-vr``. For more about the container, review [README.md](docker/README.md)

### Challenge Docker Container

We also standardized deploying course challenges (homework assignments) to our hosting infrastructure at [ctfd.io](https://ctfd.io). For usage of this container, review [README.md](challenges/README.md) .

*Course challenges (homework assignments) available to faculty on request to toconnor [at] fit.edu.*


## Lessons

We leveraged the course topics below to teach undergradaute students from the basics of stack-based binary exploitation up to advanced techniques in the kernel and heap. In each lecture, we delivered lessons that exposed the technical underpinnings of exploit techniques. Our suggested readings, slides, and demonstrations are included below. All demonstrations are included in the ``tjoconnor/undergrad-vr`` docker container and verified to work.


|        | Lessons                                     | Recommended Readings                                                                 | Class Demonstration      |
|--------|-------------------------------------------|-------------------------------------------------------------------------|-----------|
| 1      |  [ret2plt](slides/LSN1-Ret2Libc.pdf)      | [BugTraq Mailing List: lpr LIBC RETURN exploit](https://insecure.org/sploits/linux.libc.return.lpr.sploit.html)                                                              | [demo](docker/demos/ret2plt-demo)     |
| 2      | [ret2csu](slides/LSN2-Ret2CSU.pdf)        | [Return-to-csu: A new method to bypass 64-bit Linux ASLR](readings/ret2csu/UniversalGadget.pdf)             | [demo](docker/demos/ret2csu-demo)  |
| 3      | [ret2dlresolve](slides/LSN3-Ret2DLResolve.pdf) | [The advanced return-into-lib(c) exploits: PaX case study](readings/ret2dlresolve/Ret2DLResolve-Phrack.pdf) | [demo](docker/demos/ret2dlresolve-demo) solves [UTCTF Resolve Problem](https://github.com/cscosu/ctf-writeups/tree/master/2021/utctf/Resolve)  |
| 4      | [srop](slides/LSN4-SROP.pdf)              | [Framing Signals—A Return to Portable Shellcode](readings/srop/SROP.pdf)                                      | [demo](docker/demos/srop-demo) builds on [ir0nstone SROP example](https://ir0nstone.gitbook.io/notes/types/stack/syscalls/sigreturn-oriented-programming-srop/using-srop) |
| 5      | [jop](slides/LSN5-JOP.pdf)                | [Jump-Oriented Programming: A New Class of Code-Reuse Attack](readings/jop/JOP.pdf)                                         | [demo](docker/demos/jop-demo)  based On [ViolentPenTest CTFSG CG Solve](https://violenttestpen.github.io/ctf/pwn/reverse/2022/03/11/ctfsg-ctf-21/)|
| 6      | [brop](slides/LSN6-BROP.pdf)              | [Hacking Blind](readings/brop/HackingBlind.pdf)                   | [demo](docker/demos/brop-demo)  |
| 7      | [aarch64](slides/LSN7-Aarch64.pdf)        | [ROP-ing on Aarch64 - The CTF Style](readings/aarch64/aarch64.pdf)                             | [demo](docker/demos/aarch64-demo)  |
| 8      | Integer Overflows                         | [Basic Integer Overflows](readings/intoverflow/IntOverflow.pdf)                 |  |
| 9      | [Array Index Abuse](slides/LSN9-ArrayIndexAbuse.pdf) |  [Tool Interface Standard (TIS) Executable and Linking Format (ELF) Specification v.1.2](https://refspecs.linuxfoundation.org/elf/elf.pdf) | [demo](docker/demos/oob-demo)  |
| 10     | [Type Confusion](slides/LSN10-TypeConfusion.pdf) | [Unionized - CyberGames 2021 Writeup](readings/type-confusion/Type-Confusion.pdf)      | [demo](docker/demos/type-confusion-demo) based on [Knittingirl's MetaCTF Unionized Solve](https://blog.metactf.com/unionized-cybergames-2021/) |
| 11     | [Shellcode](slides/LSN11-Shellcode.pdf)   |   [Writing UTF-8 compatible shellcodes](http://phrack.org/issues/62/9.html#article)                                                                      | [demo](docker/demos/shellcode-demo) solves [UIUCTF Odd Shell](https://github.com/tj-oconnor/ctf-writeups/tree/main/uiuctf/odd_shell) |
| 12     | [Bypassing Seccomp](slides/LSN12-Seccomp.pdf) |  [A seccomp overview](https://lwn.net/Articles/656307/)                                                                     | [demo](docker/demos/seccomp-demo)  |
| 13     | [Heap Internals](slides/LSN13-Heap.pdf)   | [Malloc Internals](readings/malloc/MallocInternals.pdf)             | [demo](docker/demos/heap-demo) solves [DuCTF Login](https://github.com/tj-oconnor/ctf-writeups/tree/main/ductf/login) |
| 14     | [House of Force](slides/LSN14-House-of-Force.pdf) | [The Malloc Maleficarum](readings/malloc/MallocMaleficarum.pdf)       | [demo](docker/demos/hof-demo)  |
| 15    | [Fast Bins](slides/LSN15-FastBins-Attack.pdf) | [Guyinatuxedo: Fast Bins Overview](https://github.com/guyinatuxedo/Shogun/blob/main/bin_overviews/fastbin.md)                                                                   | [demo](docker/demos/fastbins-demo) based on [Sajjaad Arshad's BabyHeap Solve](https://github.com/sajjadium/ctf-writeups/tree/master/ctfs/0CTF/2017/Quals/babyheap) |
| 16    | [Tcache](slides/LSN16-Tcache.pdf)         | [Analysis of Malloc Protections on Singly Linked Lists](readings/tcache/Tcache.pdf)                                | [demo](docker/demos/tcache-demo) solves [NiteCTF HeapChall](https://github.com/tj-oconnor/ctf-writeups/tree/main/nitectf/heapchall) |
| 17    | [Unsafe Unlink](slides/LSN17-UnsafeUnlink.pdf) | [Vudo malloc tricks](readings/unsafe-unlink/Vudo.pdf)                           | [demo](docker/demos/unsafe-unlink-demo) based on [ir0nstone's Dream Diary Solve](https://ir0nstone.gitbook.io/hackthebox/challenges/pwn/dream-diary-chapter-1) |
| 18     | [Kernel Exploits](slides/LSN18-Kernel.pdf) | [Learning Linux kernel exploitation ](https://lkmidas.github.io/posts/20210123-linux-kernel-pwn-part-1/)                                |   |

## References

### General Binary Exploitation References

- Patrick Biernat et al., [Modern Binary Exploitation](https://github.com/RPISEC/MBE), 2015
- shellphish, [How2Heap](https://github.com/shellphish/how2heap).
- Yan Shoshitaishvili et al, [Pwn.College](https://pwn.college)
- Logan Stratton, [Temple of Pwn](https://github.com/LMS57/TempleOfPwn)
- Andrej Ljubic (ir0nstone), [Binary Exploitation Notes](https://ir0nstone.gitbook.io/notes/)
- Knittingirl [Writeups](https://github.com/knittingirl/CTF-Writeups)
- Nightmare [Binary Exploitation/Reverse Engineering](https://guyinatuxedo.github.io) Course
- Max Kamper, [ROP Emporium](https://ropemporium.com)
- TJ OConnor, [CTF Writeup Examples](https://github.com/tj-oconnor/ctf-writeups)

### Ret2PLT
- Solar Designer, [Return to Libc Exploit](https://insecure.org/sploits/linux.libc.return.lpr.sploit.html): BugTraq Mailing List (Aug 1997)
- Niklas Baumstark, [Libc Database](https://github.com/niklasb/libc-database)
- [Libc RIP](https://libc.rip)

### Ret2CSU 
- Marco-Gisbert, Hector, and Ismael Ripoll. "Return-to-csu: A new method to bypass 64-bit Linux ASLR." Black Hat Asia 2018. 2018

### Ret2dlresolve 
- Syst3mfailure, [Ret2dl_resolve x64: Exploiting Dynamic Linking Procedure In x64 ELF Binaries](https://syst3mfailure.io/ret2dl_resolve/)
- Phrack, The advanced return-into-lib(c) exploits: PaX case study
- UTCTF 21 [Resolve](https://github.com/cscosu/ctf-writeups/tree/master/2021/utctf/Resolve) Challenge

### SROP 
- Bosman, Erik, and Herbert Bos. "Framing signals-a return to portable shellcode." 2014 IEEE Symposium on Security and Privacy. IEEE, 2014.
- Michal Zalewski, [Delivering Signals for Fun and Profit](https://lcamtuf.coredump.cx/signals.txt)
- Ir0nstone, [Signal Return Oriented Programming](https://ir0nstone.gitbook.io/notes/types/stack/syscalls/sigreturn-oriented-programming-srop)

### JOP 
- Bletsch, Tyler, et al. "Jump-oriented programming: a new class of code-reuse attack." Proceedings of the 6th ACM Symposium on Information, Computer and Communications Security. 2011
- ViolentTestPen, [CTFSG CTF 2021 Writeup](https://violenttestpen.github.io/ctf/pwn/reverse/2022/03/11/ctfsg-ctf-21/)

### BROP 
- Bittau, A., Belay, A., Mashtizadeh, A., Mazières, D., & Boneh, D. (2014, May). Hacking blind. In 2014 IEEE Symposium on Security and Privacy (pp. 227-242). IEEE.
- knittingirl, [Or How to do Black-Box Pwn without Rage-Quitting](https://github.com/knittingirl/CTF-Writeups/tree/main/pwn_challs/CyberOpen22/push) Writeup

### Aarch64 ROP 
- Arm Developer, [Procedure Standard Call Documentation](https://developer.arm.com/documentation/102374/0100/Procedure-Call-Standard)
- Mark McDermott, [The ARM Instruction Set Architecture](https://users.ece.utexas.edu/~valvano/EE345M/Arm_EE382N_4.pdf)
- Perfect Blue, [ROP-ing on Aarch64 – The CTF Style](https://blog.perfect.blue/ROPing-on-Aarch64)

###  Integer Overflows 
- [Basic Integer Overflows](http://phrack.org/issues/60/10.html)  

### Array Index Abuse 
- TIS Committee, [Tool Interface Standard (TIS) Executable and Linking Format (ELF) Specification v.1.2](https://refspecs.linuxfoundation.org/elf/elf.pdf), 1995.
- Michael Matz et al., [System V Application Binary Interface AMD64 Architecture Processor Supplement](https://refspecs.linuxbase.org/elf/x86_64-abi-0.99.pdf), 1999.
 
### Type Confusion 
- Caitlin Whitehead (knittingirl), [Unionized Writeup](https://blog.metactf.com/unionized-cybergames-2021/), 2021.

### Shellcode 
- Phrack, [Writing UTF-8 compatible shellcodes](http://phrack.org/issues/62/9.html#article)
- Pwn.College: [Common Challenges Shellcoding](https://docs.google.com/presentation/d/1BHsKKkodMLXcHyqJCU0wDgexQ8jHEEiAU9Uq_Z9mibY/edit)
- X86/64 [Instruction Set Opcodes and Instructions](http://ref.x86asm.net/coder64.html)
- [Rappel](https://github.com/yrp604/rappel): A linux-based assembly REPL for x86, amd64, armv7, and armv8
- Gallopsled et al., Pwnlib Shellcraft, [Shellcode generation](https://docs.pwntools.com/en/stable/shellcraft.html)

### Bypassing Seccomp 
- LWN, [A seccomp overview](https://lwn.net/Articles/656307/)
- Pwn.College [Sandboxing Lesson](https://www.youtube.com/watch?v=Ide_eg-eQZ0)
- [LibSeccomp](https://github.com/seccomp/libseccomp) Github Repo 
- UIUCTF 2022 [No Syscalls](https://github.com/sigpwny/UIUCTF-2022-Public/tree/main/pwn/no-syscalls-allowed) Challenge 

### Heap Internals 
- Glibc Wiki, Gnu C Library [Malloc Internals](https://sourceware.org/glibc/wiki/MallocInternals) Documentation 
- Doug Lea: [A Memory Allocator](https://gee.cs.oswego.edu/dl/html/malloc.html) (Unix/Mail, 1996)
- Shellphish: [How2Heap](https://github.com/shellphish/how2heap)
- Pwn.College: [Dynamic Allocator Misuse](https://www.youtube.com/watch?v=coAJ4KyrWmY&list=PL-ymxv0nOtqr4OchXR2rV_WNhpj4ccPq1) 

### House of Force 
- Phantasmal Phantasmagoria, [Malloc Maleficarum](https://dl.packetstormsecurity.net/papers/attack/MallocMaleficarum.txt)
- Blackngel, [Malloc Des-Maleficarum](http://phrack.org/issues/66/10.html)
- How2Heap: [House of Force](https://github.com/shellphish/how2heap/blob/master/glibc_2.27/house_of_force.c) Example
- Top Chunk Size Integrity Check [Patch](https://sourceware.org/git/?p=glibc.git;a=commit;h=30a17d8c95fbfb15c52d1115803b63aaa73a285c) 
- Malloc Hooks Removed [Patch](https://patchwork.sourceware.org/project/glibc/patch/20210713073845.504356-10-siddhesh@sourceware.org/)

### Fast Bins 
- guyinatuxedo, [Fast Bins Overview](https://github.com/guyinatuxedo/Shogun/blob/main/bin_overviews/fastbin.md)
- PwnDbg, [Find Fake Fast](https://pwndbg.readthedocs.io/en/stable/commands/heap/find_fake_fast/) Command
- Sajjaad Arshad: [BabyHeap Write-up](https://github.com/sajjadium/ctf-writeups/tree/master/ctfs/0CTF/2017/Quals/babyheap)

### Tcache 
- Maxwell Dulin, [Analysis of Malloc Protections on Singly Linked Lists](https://maxwelldulin.com/BlogPost/Analysis-Malloc-Protections-on-Singly-Linked-Lists)
- Glibc Mailing List: [Add Safe-Linking to fastbins and tcache](https://sourceware.org/pipermail/libc-alpha/2020-March/111631.html)
- NiteCTF [Elementary-Tcache Challenge](https://github.com/tj-oconnor/ctf-writeups/tree/main/nitectf/heapchall)

### Unsafe Unlink 
- Glibc Source Code, [Unlink function in malloc.c](https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/malloc.c;h=ef04360b918bceca424482c6db03cc5ec90c3e00;hb=07c18a008c2ed8f5660adba2b778671db159a141)
- [Unsafe Unlink example](https://wargames.ret2.systems/level/how2heap_unsafe_unlink_2.34) at Ret2Systems that demonstrates the How2Heap Examples
- Ir0nstone, [Dream Diary: Chapter 1 Problem Writeup](https://ir0nstone.gitbook.io/hackthebox/challenges/pwn/dream-diary-chapter-1) from Hack the Box
- 0x434b, [Overview of GLIBC heap exploitation techniques: Unsafe Unlink](https://0x434b.dev/overview-of-glibc-heap-exploitation-techniques/)
- Glibc v 2.3.4 [Malloc.c Patch to prevent unsafe unlink](https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=3e030bd5f9fa57f79a509565b5de6a1c0360d953)

### Kernel Exploits
- Midas, [Learning Linux Kernel Exploitation](https://lkmidas.github.io/posts/20210123-linux-kernel-pwn-part-1/)
- Chris Roberts, [Linux Kernel Exploit Development](https://breaking-bits.gitbook.io/breaking-bits/exploit-development/linux-kernel-exploit-development)
- Pwn.College [Linux Kernel Exploit Lessons](https://www.dropbox.com/sh/90838y3y45k7yvv/AAAHfHcbUZAEYXKqBvO-eE3Ga/2020%20-%20Slides/A.%20Kernel%20Exploitation?dl=0&subfolder_nav_tracking=1)
- Temple of Pwn [Kernel Exploit Lesson](https://github.com/LMS57/TempleOfPwn/tree/main/Kernel)

## License

The course materials, slides, and docker containers were designed for academic & educational use only. 
