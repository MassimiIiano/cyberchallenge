from pwn import *
import re


def main():
    r = remote('piecewise.challs.cyberchallenge.it', 9110)
    # context.log_level = 'debug'
    while True:
        
        data = r.recvline(timeout=10).decode()
        if data == '':
            break
        
        if data.find('Partial flag') >= 0:
            print(data)
            continue
        
        number = int(re.findall(r'\d+', data)[0])
        
        if number == 10:
            r.sendline()
            continue
        
        edian = re.findall(r'big|little', data)[0]
        
        if data.find('32-bit') >= 0:
            r.send(p32(number, endianness=edian))
        else:
            r.send(p64(number, endianness=edian))
    r.close()
        
if __name__ == "__main__":
    main()