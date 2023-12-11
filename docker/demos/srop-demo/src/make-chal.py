from pwn import *
context.arch = 'amd64'
context.os = 'linux'
elf = ELF.from_assembly(
    '''
        mov rdi, 0;
        mov rsi, rsp;
        sub rsi, 8;
        mov rdx, 500;
        syscall;
        ret;

        pop rax;
        ret;
    ''', vma=0x41000
)
elf.save('chal.bin')
