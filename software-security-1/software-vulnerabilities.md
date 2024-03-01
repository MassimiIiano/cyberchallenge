# software vulnerabilities 
 - vulnerability is also knows as **attack surface**
 - A vulnerability is a weakness which can be exploited by an attacker to perform unauthorized actions within your program
- To exploit a vulnerability, an attacker relies on tool and
techniques related to a software weakness
```c
#include <stdio.h>
#include <string.h>

int main() {
    char* password = "secret";  // The password declared in main
    char* input = malloc(256);

    printf("Enter the password: ");
    scanf("%s", input); // scanf(%256s, input); to avoid buffer overflow 
                        // (not a good practice to use scanf() at all, use fgets() instead

    if (strcmp(input, password) == 0) {
        printf("Access granted.\n");
    } else {
        printf("Access denied.\n");
    }
    return 0;
}
```
- `hardcoded password` is a vulnerability
- not checking the lenght of the input is a vulnerability
- `(buffer overflow)` not checking the type of the input is a vulnerability
  - the attacker can override memory over the 256 bytes allocated

## vulnebilities vs bugs

- `Bug`: an error or a fault that causes a failure
- `Error`: a human action that produces an incorrect result
- `Fault`: an incorrect step, process, or data definition in a
computer program
- `Failure`: the inability of software to perform its required
functions within specified performance requirements

## Types of vulnerabilities
- `Buffer overflow`: a condition at an interface under which more data can be sent to a receiving program than it is able to process properly
- `information leakage`: a vulnerability that allows an attacker to gain access to information that was not intended to be accessible
- `race condition`: a vulnerability that occurs when the output of a program is dependent on the sequence or timing of other uncontrollable events
- `invalid data processing`: a vulnerability that occurs when a program does not properly validate input data