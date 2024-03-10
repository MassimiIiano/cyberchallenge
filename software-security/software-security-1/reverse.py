def rol(n: bytes, rotations: int):
    rotations %= 8
    n = ((n << rotations) & (2**8 - 1)) | (n >> (8 - rotations))
    return n

# f = open('flag.txt.aes', 'rb')
# CRYP_FLAG = f.read()

flag = ''
# for i in range(len(CRYP_FLAG)):
#     flag += chr(rol(CRYP_FLAG[i], i+1))

with open('flag.txt.aes', 'rb') as f:
    while byte := f.read(1):
        flag += chr(rol(int.from_bytes(byte), len(flag)+1))

    
print(flag)
