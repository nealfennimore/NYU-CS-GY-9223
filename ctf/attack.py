from binascii import hexlify, unhexlify

from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor
from pwn import log, remote

BLOCK_SIZE = BS = AES.block_size
iv = b'\x00'*BS

def mac_query(p: remote, msg: bytes):
    p.sendafter(b"Choice: ", b"1")
    p.sendafter(b'msg (hex): ', hexlify(msg))
    response = p.recvuntil(b'\nWhat would you like to do?')
    if b"CBC-MAC(msg): " in response:
        mac = response.split(b"CBC-MAC(msg): ")[1].split(b"\n")[0]
        log.info("MAC: %r", mac)
        return unhexlify(mac)
    
    exit(0)

def forgery(p: remote, msg: bytes, tag: bytes):
    p.sendafter(b"Choice: ", b"2")
    p.sendafter(b'msg (hex): ', hexlify(msg))
    p.sendafter(b'tag (hex): ', hexlify(tag))
    response = p.recvuntil(b'\nWhat would you like to do?')
    log.info("Response: %r", response)

with remote('0.cloud.chals.io', 12769) as r:
    # https://crypto.stackexchange.com/questions/102098/cbc-mac-forge-attack-question
    p = b"January February" # Plaintext 1
    q = b"January Februarz" # Plaintext 2

    t1 = mac_query(r, p) # Tag for p e.g. t
    t2 = mac_query(r, q) # Tag for q e.g. t'

    # We know our forged message which will have the same tag as q
    # P + (q xor t)
    forged_message = p + strxor(q, t1)

    forgery(r, forged_message, t2)
