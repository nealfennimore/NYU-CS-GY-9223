from itertools import chain
from typing import Any, Iterable, List

from pwn import *

context.binary = './heterograms'
context.terminal = ['tilix', '-e', 'bash', '-c']

chksum_placeholder = [0]
loop_one = [1]
loop_zero = [0]
loop_two = [2]

def flatten(items: Iterable) -> List[Any]:
    return list(chain.from_iterable(items))

def make_breakpoints(breakpoints: List[str]) -> List[str]:
    return list(map(lambda b: f'b* {b}', breakpoints))

def make_commands(args: List[str]) -> List[str]:
    return flatten(map(lambda a: ['-ex', a], args))

def generate_checksum(a: List[int]) -> int:
    x = 0

    for item in a:
        x += item

    if ~x < -128:
        return 128 - (abs(~x) - 128)

    return ~x


def generate_word_payload(word_cmd: List[int], before_word_cmds: List[int] = []) -> bytes:
    data = chksum_placeholder + before_word_cmds + loop_one + [len(word_cmd)] + word_cmd
    return generate_payload(data)

def generate_copy_payload(cnt_num = 0) -> bytes:
    data = chksum_placeholder + loop_two * 2 + loop_zero + [cnt_num] + loop_one + [2] + [0] * 2
    return generate_payload(data)

def generate_payload(data: List[int]) -> bytes:
    payload = [ len(data) ] + data
    payload[1] = generate_checksum(payload[2:])
    return flat(payload, word_size=8)


def to_indices(s: str) -> List[int]:
    return [(ord(c) + 7) % 26  for c in s]

words = [
    "unforgivable",
    "troublemakings",
    "computerizably",
    "hydromagnetics",
    "flamethrowing",
    "copyrightable",
    "undiscoverably",
]

breakpoints = [
    # '&process',
    # '&check'
    # '0x55555555552e', # At checksum comparison
    # '0x5555555552d6', # Compare globalstate string value index
    # '0x55555555563d', # Handle star
    # '0x5555555555f6', # Loop for 1 
    # '0x5555555555e3', # When char over 25
    '0x5555555552a2', # curr_str assignment
    '0x555555555359', # globalstate first idx is 7 check
]

print_statements = [
    # 'x/32c &globalstate',
    # 'x/11s &strs',
]

breakpoints = make_breakpoints(breakpoints)
commands = make_commands(breakpoints + print_statements + ['c'])

with process('./heterograms', aslr=False) as p:
# with remote('offsec-chalbroker.osiris.cyber.nyu.edu', 7331) as p:
    is_remote = isinstance(p, remote)

    if is_remote:
        print(p.recv())
        p.sendline(b'nf2137')

    print(p.recv())

    for idx, word in enumerate(words):
        payload = generate_copy_payload(idx)
        print(payload)
        p.send(payload)
        print(p.recvline())

        payload = generate_word_payload(
            word_cmd=to_indices(word),
            before_word_cmds=loop_zero + [idx]
        )
        print(payload)
        if not is_remote and idx == 7:
            with process(['pwndbg', '--pid', str(p.pid)] + commands) as g:
                sleep(3)
                p.send(payload)
                g.interactive()
        else:
            p.send(payload)

        print(p.recvline())

    if is_remote:
        print(p.recvline())