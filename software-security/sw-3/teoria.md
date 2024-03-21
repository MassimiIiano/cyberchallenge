# software security 3
## ACE: Arbitrary Code Execution
The attacker’s ability to execute arbitrary commands or code on a target machine or in a target process
### return to libc
A return-to-libc attack is a technique that, by using a buffer overflow, replaces a return address with the one of another function in the process memory
- discoverd by Alexander Peslyak (aka Solar Designer) in 1997

```c
#include <stdio.h>
#include <string.h>

void vulnerable_function(char *string) {
    char buffer[100];
    strcpy(buffer, string);
}

int main(int argc, char **argv) {
    vulnerable_function(argv[1]);
    return 0;
}
```

1. find the address of the system() function in the libc library
2. find the "/bin/sh" string in the libc library
3. currupt the stack to call system("/bin/sh")
   - no executable stack is needed 

```bash
$ gdb -q ./vulnerable
(gdb) b main
(gdb) p system()
(gdb) find /bin/sh
```

#### stack behavior
- stack grows from high to low memory
...

### return oriented programming
A return-oriented programming (ROP) attack is a technique that, by using a buffer overflow, replaces a return address with the one of another function in the process memory  

### jump-oriented programming
A jump-oriented programming (JOP) attack is a technique that, by using a buffer overflow, replaces a return address with the one of another function in the process memory
