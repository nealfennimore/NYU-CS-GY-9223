from itertools import chain
from typing import Any, Iterable, List

from pwn import *

context.binary = './heterograms'
context.terminal = ['tilix', '-e', 'bash', '-c']

loop_3 = [1]
loop_2 = [0]
loop_1 = [2]

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


def generate_payload(idxs: List[int], pre_idxs: List[int] = []) -> bytes:

    """
        #include <stdio.h>
        #include <stdlib.h>
        #include <string.h>


        int main()
        {
            char *the_string;
            size_t str_len;
            int i;
            
            the_string = "unforgivable";
            for (i = 0; str_len = strlen(the_string), (unsigned long)(long)i < str_len; i = i + 1) {
                printf("%c %d\n", the_string[i], ((long)(int)(unsigned int)(char)(the_string[i] + 159)) % 26 );
            }

            return 0;
        }

        u 20
        n 13
        f 5
        o 14
        r 17
        g 6
        i 8
        v 21
        a 0
        b 1
        l 11
        e 4
    """

    chksum_placeholder = [0]

    payload = chksum_placeholder + pre_idxs + loop_3 + [len(idxs)] + idxs
    payload = [ len(payload) ] + payload

    payload[1] = generate_checksum(payload[2:])

    print(payload)

    # Issue here when checksum is under `-128`.
    # It's `-134` in our case for the whole
    return flat(payload, word_size=8)


idxs_0 = [
    20, # u
    13, # n
    5,  # f
    14, # o
    17, # r
    6,  # g
    8,  # i
    21, # v
    0,  # a
    1,  # b
    11, # l
    4,  # e
]

idxs_1 = [
    -1,
    -13,  
    -8,
    2,
    -9, 
]


with process('./heterograms', aslr=False) as p:
    print(p.readline())
    
    breakpoints = [
        # '&process',
        # '&check'
        # '0x55555555552e', # At checksum comparison
        # '0x5555555552d6', # Compare globalstate string value index
        '0x55555555563d',
        '0x5555555555f6', # Loop for 1 
        # '0x5555555555f6',
    ]

    print_statements = [
      'x/32c &globalstate',
      'x/11s &strs',
    ]

    breakpoints = make_breakpoints(breakpoints)
    commands = make_commands(breakpoints + print_statements + ['c'])

    payload = generate_payload(idxs_0)
    print(payload)
    p.write(payload)
    print(p.readline())

    payload = generate_payload(idxs_1, pre_idxs=loop_2 + [1])
    print(payload)
    with process(['pwndbg', '--pid', str(p.pid)] + commands) as g:
        sleep(3)
        p.write(payload)
        g.interactive()
        print(p.readline())
