from binascii import hexlify

from Crypto.Cipher import AES
from pwn import *
from pwn import log, remote

BLOCK_SIZE = AES.block_size
iv = bytes.fromhex('7dc4885cc38ef6fd0181b78f8f484873')
ciphertext = bytes.fromhex('f4a60fdec121df64f0dca2abcb8cb82507b20ee6da804da255714b7b588329b862346ef2154f49906105da6e6642dc63a7b71afbf2b37a1bfdf56714259150845e44e163cab0007ae53568635cab963f357916970c92c21e1c62fc57f1507c0ae8df7d24107335c7db653e32a4777005872d5118f391a72f7fd3d2befd0a13e273adfb2d514dc091af279b18666c9cf047559891a00b0b8f95db7d4428cc6447ab9fa3519025225bb0fb59b7a49c9540d9a57d73b0af7ca35d626726d813fbf4e632be6c4099019af1178ae83b00145db228e716a75a22ce147496a96c14cbae68c258d3631451001972106cc3a28041fb4b3bb618ade618f4d4b804c0dd207d94ea99fe499fd5555ee112f8307a2b9430cdebdccb9ea29a9e0a08d7395006c9c9b4fb57b3eb5b3b12ddf16e911970521fd92e4521615179c838f9af3c2ae44d56992c620e9b9e087dac9029d3ee6fb4dc4731479ff1d73f9fe70fbc53f13dd4c8d2ccab9fd7f12a555549c0701c5c61898bf144007c51f6bb518ebbdd8261f72f4035cbe8d41653de008c8be5c4a115649f87a1127818d8183b048ac060e3e4efbac7818561284fd0286f228f129e5b898a122162744853206cc710f3f4ccafd89447f60dd84b698124714b64f01c2bdd09dc898a951f3cce109258a2ed9b27d406699f404e5f762f9b8714382305e63b5f8b1eecbbe886cf7c5dadf7e5176eb40e88fd5c63211765e7e6b1a0e38550476cae5d4ae803e2b01613969072f5da3672b681897d9be871c66b03b08c58172d49c97f195c3a21a9f5a914c8800a5a464ce47670b598ab66451b043910709891b0782d16f9772a711fc687bdf892edf5b2a0d3e402f20fa80998f409b124fac4aa7555988330eea31f41994af48201e7cbc40510f2f63486badacf4c2d9771e0ac6b57fb0ddc0c0f413d938d52f118fe577197e8f838b30f807ce10c863211022740822c494f12305c0f1d04c9713e3ddb179617e0ad693b6a6b3892309f55d1cc20145210446afe1abca56a6803209fb8f6300679e8c6db248f91db50923ce1ba1fe9410bc912569cc4ffc87cae1a25261d6d13400c9091f3c1c45c1a256a041421c2f7eca08005d4e8ae5ad255cf7a67c07a941a4217e3e1389ea612242b7b040149f54eab4b9b6b9acd78a5fc823cde075d10f7b601e42bb23e00852ed1a0898622f34fe8687657901a3553323d63c7a9d7e9395787918b4b5fd062bf915b9cf7fe4580ddf312337311f5f2ed959014c669643d17757a5b796ecaff9b3a9725c1342528c35b7ab59e6dfd432dcee5a636dd63e75165c2c3bb57b2e13c6b')

def oracle(p: remote, payload: bytes) -> bool:
    p.sendlineafter(b'Gimme a message: ', hexlify(payload))
    response = p.recvuntil(b'Messages should be hex strings, in the format [IV][Ciphertext].')
    is_valid = b"yep, that's a valid message" in response
    if is_valid:
        log.info("Found match: %r", hexlify(payload))
    return is_valid


# From https://github.com/flast101/padding-oracle-attack-explained/blob/master/poracle_exploit.py
def attack(p: remote):
    block_number = len(ciphertext)//BLOCK_SIZE
    decrypted = bytes()
    # Go through each block
    for i in range(block_number, 0, -1):
        current_encrypted_block = ciphertext[(i-1)*BLOCK_SIZE:(i)*BLOCK_SIZE]

        # At the first encrypted block, use the initialization vector if it is known
        if(i == 1):
            previous_encrypted_block = bytearray(iv)
        else:
            previous_encrypted_block = ciphertext[(i-2)*BLOCK_SIZE:(i-1)*BLOCK_SIZE]
 
        bruteforce_block = previous_encrypted_block
        current_decrypted_block = bytearray(iv)
        padding = 0

        log.info("Decrypted: %r", decrypted)
        log.info("On block: %d", i)
        log.info("Prev block: %r", hexlify(previous_encrypted_block))

        # Go through each byte of the block
        for j in range(BLOCK_SIZE, 0, -1):
            padding += 1

            # Bruteforce byte value
            for byte in range(0,256):
                bruteforce_block = bytearray(bruteforce_block)
                bruteforce_block[j-1] = (bruteforce_block[j-1] + 1) % 256
                joined_encrypted_block = bytes(bruteforce_block) + current_encrypted_block

                # Ask the oracle
                if(oracle(p, joined_encrypted_block)):
                    current_decrypted_block[-padding] = bruteforce_block[-padding] ^ previous_encrypted_block[-padding] ^ padding

                    log.info("Found for byte: %d", byte)

                    # Prepare newly found byte values
                    for k in range(1, padding+1):
                        bruteforce_block[-k] = padding+1 ^ current_decrypted_block[-k] ^ previous_encrypted_block[-k]

                    break

        decrypted = bytes(current_decrypted_block) + bytes(decrypted)

    return decrypted[:-decrypted[-1]]  # Padding removal

with remote('offsec-chalbroker.osiris.cyber.nyu.edu', 1478) as p:
    p.recvuntil(b'Please input your NetID (something like abc123): ')
    p.sendline(b'nf2137')

    response = attack(p)

    print(response)
