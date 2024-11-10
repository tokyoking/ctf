# Catagory: PWN
## Description
### Level: Easy

![descriptoon](https://github.com/user-attachments/assets/340cad2d-56ad-4d30-95a4-044895d56838)

## Approach

Even if we know this is a shellcode challenge from the description, it's still important to check the properties of the binary.

![chkcsec](https://github.com/user-attachments/assets/eee19196-3b70-4c93-a55a-35598c351996)

No stripped, rest is up. No good :*

## Running the binary

![runbinary](https://github.com/user-attachments/assets/0c5dc3b7-09f7-4603-ae42-309ed8e725c1)

Very straigthforward.

If you disassemble main, you'll see a call for **blacklist** function. As the name suggest our shellcode getting filtered.

![blckisr](https://github.com/user-attachments/assets/cc547734-8802-45fa-ae08-964176407fcc)

I wrote a simple assembly just exiting with the error code 404. 

![exit](https://github.com/user-attachments/assets/14670131-cc16-441e-a7ed-56c193f77d2a)

We see the opcode **0f**, its probably for **syscall** instruction. 

![syscall](https://github.com/user-attachments/assets/0eacb93e-b204-4450-a1c4-ec159d829173)

Yup, we confirmed it. Snippet is from really cool source for x86 and amd64 instruction references: https://www.felixcloutier.com/x86

## Thinking about how to bypass the filter

Instead of calling syscall, we can call another instruction that switchs to kernel mode which is **int 0x80**. Its opcode is "cd 80" and bypasses the filter. Also, we can write a self modifying assembly so it would change itself at runtime.

Both pretty simple to pull off.

## What are the other restrictions?

![memset](https://github.com/user-attachments/assets/54cfd842-2657-4b55-924c-7ea72da8dbec)

Running *ltrace* on the binary, we'll see that it's calling **mmap**, **memset** and **mprotect** for the address **0x13370000**. Safe to assume this is the address we write into our shellcode. If you don't know ltrace or any of the calls above, *manpages* will be your best friend sooner or later. 

![mprotect](https://github.com/user-attachments/assets/3f0b170f-0675-42e4-a07f-05b5ee610782)
But I should mention that if you want to do a self modifying shellcode, you should make sure that you have **PROT_WRITE** permission for it. Otherwise it won't let you modify the memory. If we look at the output of ltrace, we'll see that **mprotect** is called with **0x4** flag, meaning that it is only executable. 

We can confirm it with **vmmap** command in gef.

![execute](https://github.com/user-attachments/assets/749cf93c-73a6-405a-8f73-990416e1302d)

One way to overcome this, is to call **mprotect** again with the needed flags. Simple, yet effective. I did both self-modifying and int 0x80 method in my shellcode.





