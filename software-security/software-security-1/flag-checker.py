# hex_string = "54 00 00 00 c3 00 00 00 22 01 00 00 8b 01 00 00 df 01 00 00 44 02 00 00 b6 02 00 00 ea 02 00 00 5e 03 00 00 c3 03 00 00 22 04 00 00 8b 04 00 00 c0 04 00 00 1f 05 00 00 87 05 00 00 dc 05 00 00 49 06 00 00 aa 06 00 00 f8"
# arr = list(map(lambda x: int(x, 16), hex_string.split(' ')))

import struct


MEM = b'\x54\x00\x00\x00\xc3\x00\x00\x00\x22\x01\x00\x00\x8b\x01\x00\x00\xdf\x01\x00\x00\x44\x02\x00\x00\xb6\x02\x00\x00\xea\x02\x00\x00\x5e\x03\x00\x00\xc3\x03\x00\x00\x22\x04\x00\x00\x8b\x04\x00\x00\xc0\x04\x00\x00\x1f\x05\x00\x00\x87\x05\x00\x00\xdc\x05\x00\x00\x49\x06\x00\x00\xaa\x06\x00\x00\xf8\x06\x00\x00\x57\x07\x00\x00\xcb\x07\x00\x00\xfb\x07\x00\x00\x5a\x08\x00\x00\xcc\x08\x00\x00\xff\x08\x00\x00\x42\x09\x00\x00\xb7\x09\x00\x00\x09\x0a\x00\x00\x7c\x0a\x00\x00\xe1\x0a\x00\x00\x40\x0b\x00\x00\xa4\x0b\x00\x00\xd5\x0b\x00\x00\x4b\x0c\x00\x00\xb4\x0c\x00\x00\x22\x0d\x00\x00\x87\x0d\x00\x00\xff\xff\xff\xff'

def bytes_to_ints(bytes_list):
    ints_list = []
    for i in range(0, len(bytes_list), 4):
        byte_group = bytes_list[i:i+4]
        integer = struct.unpack('<I', bytes(byte_group))[0]
        ints_list.append(integer)
    return ints_list

# 1010
# 0101
MEM_INTS = bytes_to_ints(MEM)

def getflag(ints):
    flag = f'{chr(ints[0])}'
    
    for i in range(1, len(ints) - 1):
        flag += f'{chr((ints[i] - ints[i-1]))}'
        
    return flag
    
print(getflag(MEM_INTS))
