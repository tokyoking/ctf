# Catagory: PWN
## Description
### Level: Easy

![descriptoon](https://github.com/user-attachments/assets/340cad2d-56ad-4d30-95a4-044895d56838)

## Approach

Even if we know this is a shellcode challenge from the description, it's still important to check the properties of the binary.

![chkcsec](https://github.com/user-attachments/assets/eee19196-3b70-4c93-a55a-35598c351996)

No stripped, rest is up. 

## Running the binary

![runbinary](https://github.com/user-attachments/assets/0c5dc3b7-09f7-4603-ae42-309ed8e725c1)

Very straigthforward.

If you disassemble main, you'll see a call for **blacklist** function. As the name suggest our shellcode is getting filtered.

![blckisr](https://github.com/user-attachments/assets/cc547734-8802-45fa-ae08-964176407fcc)

I wrote a simple assembly calling **exit** with the error code 404. 

![exit](https://github.com/user-attachments/assets/14670131-cc16-441e-a7ed-56c193f77d2a)

We see the opcode **0f 05**, its probably for **syscall** instruction. 

![syscall](https://github.com/user-attachments/assets/0eacb93e-b204-4450-a1c4-ec159d829173)

Yup, confirmed it. Snippet is from really cool source for x86 and amd64 instruction references: https://<!--TESTING-->www.felixcloutier.com/x86

## Thinking about how to bypass the filter

Instead of calling syscall, we can call another instruction that switchs to kernel mode,**int 0x80**. Its opcode is **cd 80**, bypasses the filter. Also, we can write a self modifying assembly so it would change itself at runtime.

Both pretty simple to pull off. I did both self-modifying and int 0x80 method in my shellcode.

## What are the other restrictions?

![memset](https://github.com/user-attachments/assets/54cfd842-2657-4b55-924c-7ea72da8dbec)

Running *ltrace* on the binary, we'll see that it's calling **mmap**, **memset** and **mprotect** for the address **0x13370000**. Safe to assume this is the address we write into our shellcode. If you don't know ltrace or any of the calls above, *manpages* will be your best friend sooner or later. 


But I should mention that if you want to do a self modifying shellcode, you should make sure that you have write permissions for the address. Otherwise it won't let you modify the memory and SEGFAULT. If we look at the output of ltrace, we'll see that **mprotect** is called with **0x4** flag, meaning that it is only *executable*. 

We can confirm it with `vmmap` command in `gef-gdb`.

![execute](https://github.com/user-attachments/assets/749cf93c-73a6-405a-8f73-990416e1302d)

One way to overcome this, is to call **mprotect** again with the needed permission flags. Simple, yet effective. 

Okay, I called **mprotect** again and made a self modfying shellcode. Are we done? Turns out *no*, there are few more hills to climb before the flag.

![badbyte](https://github.com/user-attachments/assets/9b3d61d7-ec1f-483a-a7fc-d559ba2939a3)

See the bad byte here? It gets incremented at runtime and turn into the opcode for **syscall**. So far so good.

![bdbytesrnadom](https://github.com/user-attachments/assets/faaebb9c-7685-4292-b681-4da8773accda)

Wait, now we have more bad bytes and random instructions? Why? Because our string is in the **code** section. Meaning that "/bin/bash" will disassemble to its bytes and the opcodes try to match instructions if such opcodes for instructions exist, and if not, the program will terminate with signal **SIGILL** (illegal instruction). Hence we call them the **bad bytes**. 

How can we prevent our string to be interpreted as opcode? With writing it onto the "stack"! (not sure if this is the correct way to word it)

![rsp](https://github.com/user-attachments/assets/b34a0ccf-91ef-4e48-99fb-366e0aa7f88c)

In the binary, **rsp** is pointing to "0". Ways to change it? We can `mov rbp, 0x13370000` so it holds the address and `leave`. This will make stack pointer to point "0x1337000". Because `leave` is just `mov rsp, rbp` and `pop rbp`. 

![stack](https://github.com/user-attachments/assets/bcf38830-bd95-4eff-8412-e699fda5912d)

## Debugging your shellcode

Before we leave, you can `gcc -nostdlib -static shellcode.s -o shellcode-elf` to turn your assembly to an elf object and `objcopy --dump-section .text=shellcode-raw shellcode-elf` to get the raw bytes. To debug add `int3` in your assembly. Also, `hd shellcode-raw` will hexdump it so you can see the raw bytes and `strace ./shellcode-elf` to trace your syscalls.

![flag](https://github.com/user-attachments/assets/3167bf08-b16b-4006-9121-409b65b28a73)







