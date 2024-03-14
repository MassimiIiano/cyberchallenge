def rol(n: bytes, rotations: int) -> int:
    rotations %= 8
    n = ((n << rotations) & (2**8 - 1)) | (n >> (8 - rotations))
    return n

# 10101010 << 2 = 1010101000
# 1010101000 & 01111111 = 00101000

# 10101010 >> 6 = 00000010
# 00101000 | 00000010 = 00101010

f = open('flag.txt.aes', 'rb')
CRYP_FLAG = f.read()

flag = ''
    

with open('flag.txt.aes', 'rb') as f:
    while b := f.read(1):
        flag += chr(rol(int.from_bytes(b), len(flag)+1))

    
print(flag)
