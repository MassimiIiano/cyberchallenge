## browser wars
in the browser wars in the race to implement new feautures a vast varaity of standards were created and implemented by different browsers. This caused a lot of confusion and frustration for developers. it also allowed for a lot of security vulnerabilities to be introduced.

## HTTP overvew

### schema
- usually http or https
  - specifies the protocol to use
- host & port
  - specifies the server to connect to
- url-path
  - specifies the resource to request
  - `/<directory>/<file>?<query>#<fragment>&<query>`
  - `?` separates the path from the query
  - `#` separates the query from the fragment
  - `&` separates multiple queries
  - special characters are encoded as `%<hex>`

### request and response
- request
  - method
    - GET, POST, PUT, DELETE, HEAD, OPTIONS, TRACE, CONNECT
      - Post: send data to the server
      - Get: request data from the server
      - Put: update data on the server
      - Delete: delete data on the server
      - Head: get the headers of the response
      - Options: get the options of the server
      - Trace: get the path of the request
      - Connect: establish a tunnel to the server
  - newline separated headers form body
  - body is ended by the characters `\r\n\r\n`
  - headers
    - key-value pairs
    - used to send additional information
      - Host is mandatory
        - specifies the server to connect to
      - status line
        - version
        - integer number
          - 1**: informational
          - 2**: success
          - 3**: redirection
          - 4**: client error
          - 5**: server error
        - string
    - Content-Type
      - application/x-www-form-urlencoded
      - application/json
      - multipart/form-data
  - body
    - data to send

### Cookies
Cookis are text information witch make HTTP Statefull
- sent with every request
- session management
- personalization
- managing user state

### attak types
#### file disclosure
a file disclosure is the impact of ceratin vulnerabilities that allow an attacker to access files that are not intended to be accessed. this can be done by exploiting a vulnerability in the web server or the application itself.

- in many application user-uploaded files are the target
- configuration files are also a target
- steal the source code
- the attacker can use the information to further attack the system

#### path traversal
path traversal is a type of attack that allows an attacker to access files and directories that are outside the web root directory. this can be done by exploiting a vulnerability in the web server or the application itself.
- full pain path traversal
  - leaks every file on the system
  - can change comunication protocoll
- append path traversal
  - leaks only the file that is requested
  - can't change the communication protocoll
- prepended path traversal
  - worked well on older versions of php
  - some languages use the c open function to open a file
  - appending the null byte to the file name will stop the file from being opened
- blacklisting
  - looks for specific strings and blocks or patches them
  - not always woirks

### fixex
#### chroots
- os or programming language jails the directory and cannot be acessed
#### enforce normalisated paths
