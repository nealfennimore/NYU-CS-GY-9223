import binascii
import string
from itertools import combinations

# chars = list(string.punctuation)
# f = open('sb-ciphertext.txt','r').read()
chars = list(string.ascii_letters)
f = open('mb-ciphertext.txt','r').read()
decoded = binascii.unhexlify(f)

def xor(data: bytes, key: bytes):
    output = bytearray()
    key_length = len(key)

    for i, d in enumerate(data):
        k = key[i % key_length]
        output.append(
            d ^ k
        )

    return output.decode('utf-8', errors='ignore')

for length in range(1, 10):
    found = False

    for comb in combinations(chars, length):
        key = ''.join(comb).encode()
        output = xor(decoded, '')
        if 'flag{' in output:
            found = True
            print(''.join(comb), output)
            break

    if found:
        break

