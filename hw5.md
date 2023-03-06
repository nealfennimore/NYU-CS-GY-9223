START: 0x555555555080 FUN_00101080
NEXT: FUN_00101f40 
    - Before input ask: 0x7ffff7dd728e
    - ??? 0x7ffff7dd7304 -> 0x7ffff7dd7309

NEXT: FUN_00101120


del br
b *0x555555555080


b *0x555555555c03
b *0x5555555553fe
b *0x555555555434

b *0x555555555359 # Beginning of ask for input function call
b *0x555555555376 # End of ask for input function call

b *0x5555555554d4
b *0x555555555586

b *0x5555555553d7

b *0x555555555c08 # Check result against expected for next phase

b *0x5555555555f3

0x56172583a140

# b *0x7ffff7dd71d0
# b *0x7ffff7deb8a0
# b *0x7ffff7dd724e
# # b *0x7ffff7dd7255

# b *0x7ffff7dd7255
# b *0x7ffff7dd724c
# b *0x555555555930

# b *0x555555555964

# b *0x555555555982

# b *0x555555555392

# b *0x5555555553fe