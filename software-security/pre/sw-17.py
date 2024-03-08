#!/usr/bin/env python3

# Importa la libreria di pwntools
from pwn import *


def main():
    '''
    remote(hostname, port) apre una socket e ritorna un object
    che può essere usato per inviare e ricevere dati sulla socket  
    '''
    HOST = "software-17.challs.olicyber.it"
    PORT = 13000
    r = remote(HOST, PORT)


    # .recv() riceve e ritorna al massimo 1024 bytes dalla socket
    r.recv(1024)
    r.sendline()
    
    # get data and remove first line
    
    for _ in range(10):
        data = r.recv(1024).decode()
        print(data)
        data = data.splitlines()[1:]
        data = ''.join(data)
        
        # transform string to list of integers
        arr = list(map(
            int,
            data[data.find('[')+1:data.find(']')].split(',')
        ))
        # send the response
        r.sendline(f"{sum(arr)}".encode())
    
    
    print(r.recv(1024).decode())

    # chiude la socket
    r.close()



if __name__ == "__main__":
    main()
