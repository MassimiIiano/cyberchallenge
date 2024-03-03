from pwn import *
from pwnlib.util.packing import p32

binary = ELF('/home/spatola/cyberchallenge/software-security-1/flag_checker')

# Assuming that the value at 0x00104020 is a 32-bit integer
binary.write(0x00104020, p32(0xff))

binary.save('modified_flag_checker')