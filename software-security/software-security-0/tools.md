## given an executable (elf) we can

1. if the file is **executable**
2. discover the **architecture**
3. collect **symbols** and **strings** used in the programm
4. check if running process is asociated with the binarry
5. read the **SHA** of a file and check if it is associated with some **malware**
6. identify **function name** and **libraries** used in the programm

### tools we can use
- strins
  - collects all the strings in a binarry file
- objdump
  - information from the overoll header of each object file
- readelf

## GNU project debugger

call with `gdb <program>` or for running programms `gdb -p <pid>`

## pwntools
exploit writing as simple as possible

- tubes (i/o port wrapper)
  - serial I/O ports
  - process running on ssh
  - romote tcp or udp
  - local processes (pipe)