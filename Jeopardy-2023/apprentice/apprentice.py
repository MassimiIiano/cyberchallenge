#!/usr/bin/env python3
from Crypto.Hash import SHA3_384

def enc(plain):
    res = b''
    for c in plain:
        res += SHA3_384.new(bytes([c])).digest()[:2]
    return res.hex()


def dec(cipher):
    res = b''
    for i in range(0, len(cipher), 2):
        res += bytes([int(cipher[i:i+2], 16)])
    print(res)

if __name__ == '__main__':
    with open('/workspaces/cyberchallenge/Jeopardy-2023/apprentice/apprentice_output.txt', 'rw') as wf:
        print(dec(wf.read()))

