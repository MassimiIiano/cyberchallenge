from pwn import *

# Set up the connection
conn = remote('192.168.100.3', 38201)

# Send and receive data
conn.sendline('Hello, server!')
response = conn.recvline()

# Close the connection
conn.close() 
