from pwn import *

binary = args.BIN
e = context.binary = ELF(binary, checksec=False)

log.info('Discovering gadgets for binary')
log.info('------------------------------')
r = ROP(e)

log.info('Discovering Gadgets')
for gadget in r.gadgets:
    log.info('%s: %s' % (gadget, r.gadgets[gadget]))

log.info('\nDiscovering Available Symbols')
log.info('-----------------------------')
for symbol in e.plt:
    log.info('%s' % symbol)
