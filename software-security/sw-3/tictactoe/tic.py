from pwn import *

exe = ELF('./tictactoe')
context.binary = exe

io = remote("tictactoe.challs.cyberchallenge.it", 9132)
