#!/usr/bin/env python3

# Importa la libreria di pwntools
from pwn import *


def main():
    '''
    remote(hostname, port) apre una socket e ritorna un object
    che può essere usato per inviare e ricevere dati sulla socket
    '''
    context.log_level = 'debug'
    exe = ELF('./sw-19')
    # p = process(exe.path)
    
    HOST = "software-19.challs.olicyber.it"
    PORT = 13002
    r = remote(HOST, PORT)


    # remove first message
    # p.recv(1024)
    r.recv(1024)
    r.sendline()
    r.recv(1024)
    r.sendline()
        
    for i in range(20):
        # get data from socket
        data = r.recv(1024).split()[1].decode()
        data = data.replace(':', '')
        ret = exe.sym[data]

        r.sendline(f'{hex(ret)}'.encode())
        
    print(r.recv(1024).decode())
    r.close()



if __name__ == "__main__":
    main()
