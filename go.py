from pwn import *

context.terminal = ['code']

gdb.debug('./hand_rolled_cryptex')
