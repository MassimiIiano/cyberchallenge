# secure programming
## sicurity principles

- software must be **quality software**
- software must be **reliable software**
- software must be **secure software**

### attacker's advantages
- attacker can chose the weakest point
- attacker can chose probe for unknown vulnerabilities
- attacker can strike at will
- attacker can use criminal tactics

### learn form mistakes
- how did the security error occur
- is the problem present in other areas of the system
- how could the error be prevented
- how could the error be detected
- how could the error be fixed
- **write a report about the security issue**

### minimize the attack surface
- not needed modules shoud be disabled/removed
- identify secure configuration of the software

### security principles
- `defense in depth`: not rely on other systems to protect your software
- assume external systems are unsecure (especialy if imput comes form useres)

### secure software development
#### defensive programming
`Never assume anything`! check all assumptions and handle every possible state.
each procedure/functiunality/module should:
- identify **preconditions**, (predicate must be true before execution)
- add appropiate statements to check preconditions
- keep tack of preconditions and **include them in the documentation**

#### security by design
- `design phase`
  - `threat modeling`: identify potential threats and vulnerabilities
- 