| File type | owner | group | others | hard links | owner | file size | last modified | filename |
|-----------|-------|-------|--------|------------|-------|-----------|---------------|----------|
| \-        | rw-   | rw-   | r--    | 1          | user  | 790       | date          | file.txt |

## UMask
File: 666 rw-  
Dir:  777 rwx  

umask default  
0002 -> 664  
| special | owner | group | others |
|---------|-------|-------|--------|
| 0       | 0     | 0     | 2      |
| ---     | ---   | ---   | -w-    |

r = 4  
w = 2  
x = 1  

# Access Control
## Discretionary Access COntrol (DAC)
- Mais comum em sistemas UNIX.
- owner define permissões.

## Mandatory Access Control (MAC)
- administradores ou sistema definem permissões.

## Role-Based Access Control (RBAC)
- permissões com base no role.

## Attribute-Based Access Control (ABAC)
- permissões com base em comdições (tempo, localização, etc.)