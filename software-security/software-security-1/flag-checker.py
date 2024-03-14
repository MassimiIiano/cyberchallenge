# hex_string = "54 00 00 00 c3 00 00 00 22 01 00 00 8b 01 00 00 df 01 00 00 44 02 00 00 b6 02 00 00 ea 02 00 00 5e 03 00 00 c3 03 00 00 22 04 00 00 8b 04 00 00 c0 04 00 00 1f 05 00 00 87 05 00 00 dc 05 00 00 49 06 00 00 aa 06 00 00 f8"
# arr = list(map(lambda x: int(x, 16), hex_string.split(' ')))
MEM = [84, 0, 0, 0, 195, 0, 0, 0, 34, 1, 0, 0, 139, 1, 0, 0, 223, 1, 0, 0, 68, 2, 0, 0, 182, 2, 0, 0, 234, 2, 0, 0, 94, 3, 0, 0, 195, 3, 0, 0, 34, 4, 0, 0, 139, 4, 0, 0, 192, 4, 0, 0, 31, 5, 0, 0, 135, 5, 0, 0, 220, 5, 0, 0, 73, 6, 0, 0, 170, 6, 0, 0, -1]

FLAG = [84, ]

def hellscape(i: int = 0, prev: int = 0):
    prev += int(FLAG[i])
    
    # if MEM[i] < 0:
    #     return f"success: {FLAG}"
    
    if prev == MEM[i]:
        hellscape(i + 1, prev)
    
    hellscape(i, prev - int(FLAG[i]))
    
def flag():
    flag = [MEM[0]]
    
    for i in MEM[1:]:
        flag.append()