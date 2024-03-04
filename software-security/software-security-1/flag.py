from pwn import*

binary = ELF('/home/spatola/cyberchallenge/software-security-1/slow_printer')
binary.write(0x0040124b, asm('nop') * 5)
binary.save('quick_printer')