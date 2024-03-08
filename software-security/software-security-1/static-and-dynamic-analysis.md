# static and dynamic analysis

**Static Analysis**
- extracting data from binary 
- discovery of vulnerabilities

**Dynamic Analysis**
- memory leaks
- anti debug protection techniques

## gathering information form binary

- see if programm is **executable**
- discover **architecture**
- **symbols** and **strings** used in binary
  - wget -q -O- https://github.com/hugsy/gef/raw/master/scripts/gef.sh | sh