#!/usr/bin/env python3

# Importa la libreria di pwntools
from pwn import remote, context, p32, p64


def main():
    '''
    remote(hostname, port) apre una socket e ritorna un object
    che può essere usato per inviare e ricevere dati sulla socket
    ```
    def main():
        print('main')
    ```  
    '''
    context.log_level = 'debug'
    HOST = "software-18.challs.olicyber.it"
    PORT = 13001
    r = remote(HOST, PORT)


    # .recv() riceve e ritorna al massimo 1024 bytes dalla socket
    r.recv(1024)
    r.sendline()
    
    
    # get data and remove first line
    
    for _ in range(100):
        # get data from socket
        data = r.recv(1024)

        data = data.split()
        num = int(data[5], 16)

        if data[8] == b'32-bit':
            # ret = p32(num, "signed", "little")
            ret = p32(num)
        else:
            # ret = p64(num, "signed", "little")
            ret = p64(num)
        
        r.send(ret)
        
    r.recv(1024)
    # chiude la socket
    r.close()



if __name__ == "__main__":
    main()
