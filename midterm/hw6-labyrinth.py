from itertools import chain, permutations, product
from typing import Any, Iterable, List, Tuple

from pwn import *

context.binary = './labyrinth'
context.terminal = ['tilix', '-e']

def flatten(items: Iterable) -> List[Any]:
    return list(chain.from_iterable(items))

def make_breakpoints(breakpoints: List[str]) -> List[str]:
    return list(map(lambda b: f'b* {b}', breakpoints))

def make_commands(args: List[str]) -> List[str]:
    return flatten(map(lambda a: ['-ex', a], args))

def to_ord(s: str) -> List[int]:
    return list(map(lambda c: ord(c), s))

breakpoints = [
    # '&main',
    # '&traverse',
    # '0x400834', # Total
    # '0x400855', # Compare to L
    # '0x40086c', # Compare to R
    # '0x40087c', # Increment loop by 1
    # '0x40083b', # Before loop
    # '0x40088c', # Set cntr
    # '0x40084e', # Update total
    # '0x40085d', # Increment for L
    # '0x400874', # Increment for R
    # '0x40084b', # New total
    '0x400859', # L
    '0x400870', # R
]

print_statements = [
    'p/d $eax', # The 
    'p $al', # Value of *i when CMP
    'x/d $rbp - 8', # The current increment
    'x/d $rbp - 0x18', # The current i
    'x/d $rbp - 0xc', # Total
]

breakpoints = make_breakpoints(breakpoints)
commands = make_commands(breakpoints + print_statements)

R = 'R'
L = 'L'
v = 'value'

the_map = {
    # 227
    'a': {
        L: 'c',
        R: 'g',
    },
    # 505
    'b': {
        L: 'e',
        R: 'd'
    },
    # 1128
    'c': {
        L: 'd',
        R: 'g'
    },
    # 531
    'd': {
        L: 'i',
        R: 'd'
    },
    # 289
    'e': {
        L: 'f',
        R: 'h'
    },
    # 937
    'f': {
        L: 'a',
        R: 'f'
    },
    # 410
    'g': {
        L: 'j',
        R: 'a'
    },
    # 314
    'h': {
        L: 'a',
        R: 'j'
    },
    # 866
    'i': {
        L: 'j',
        R: 'b'
    },
    # 710
    'j': {
        L: 'j',
        R: 'd'
    },
}

chars_to_value = {
    'a':227,  # L1 # R1 R3 R5
    'b':505,
    'c':1128, # L2
    'd':531,  # L3
    'e':289,
    'f':937,
    'g':410,  # R2 R4
    'h':314,
    'i':866,  # L4
    'j':710,  # L5 L6 L7
}

SOLUTION = 9595
def solve_map(start: str, total:int, path: str) -> Tuple[bool, str]:
    nxt = the_map[start]

    nxt_L_inc = chars_to_value[nxt[L]]
    nxt_R_inc = chars_to_value[nxt[R]]

    if total + nxt_L_inc == SOLUTION:
        return (True, path + L)

    if total + nxt_R_inc == SOLUTION:
        return (True, path + R)

    if total + nxt_L_inc < SOLUTION:
        r = solve_map(nxt[L], total + nxt_L_inc, path + L)
        if r[0]:
            return (True, r[1])

    if total + nxt_R_inc < SOLUTION:
        r = solve_map(nxt[R], total + nxt_R_inc, path + R)
        if r[0]:
            return (True, r[1])

    return (False, path)

fail_cases = ["You have been eaten by a grue.\n"]
def debug_process(cmd: str) -> bool:
    print(cmd)
    payload = to_ord(cmd)
    print(payload)
    payload = flat(to_ord(cmd), word_size=8)
    print(payload)
    is_success = False

    with process('./labyrinth', aslr=False) as p:
        l = p.recvline()

        with process(['pwndbg', '--pid', str(p.pid)] + commands) as g:
            sleep(3)
            p.send(payload)
            g.interactive()

        l = p.recvline()
        is_success = l.decode() not in fail_cases

    return is_success

# debug_process("")

with remote('offsec-chalbroker.osiris.cyber.nyu.edu', 1253) as p:
    is_remote = isinstance(p, remote)

    if is_remote:
        print(p.recv())
        p.sendline(b'nf2137')

    sleep(5)
    print(p.recv())

    (_, path) = solve_map('a', 0, '')
    print(path)
    p.sendline(path.encode())
    print(p.recvline())

    if is_remote:
        print(p.recvline())