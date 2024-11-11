# Catagory: PWN
## Description
### Level: Easy

![rev](https://github.com/user-attachments/assets/622e82e4-df37-4565-9036-42abf4e692b9)

Shellcode_runner3 but with a revenge! The previous challenge didn't restrict `int 0x80` due to some compile issue so `int 0x80` was an unintended solution (what i've heard from Discord). In this revenge version, both `int 0x80` and `syscall` filtered out. The rest is the same. 

## Approach

I could've solved this only if I typed `info registers` like every sane person `gdb`.

![fsbase](https://github.com/user-attachments/assets/fca1fa33-7fa9-4246-9644-e9a8ca936b65)

We see that `fs_base` register isn't cleared so we can leak anything we want. Especially **libc** for reasons you'll see in a minute. 

![vmmap](https://github.com/user-attachments/assets/988872a9-bf13-4e59-b5c8-e586c7364992)

`vmmap` or `info proc mappings` in gdb if you don't have gef extansion will show the mapped memory regions. Here we see the start of **libc**. 

![libcaddr](https://github.com/user-attachments/assets/d2ae80ea-27d4-47a0-a420-c8c2b979bf85)

We can find the offset to **libc base** with some offset from **fs_base** then we can do anything we want. We can do a similar approach and jump to **mprotect** with PROT_WRITE flag to do a self-modfying shellcode. But it'd be lame to do the same method again. Instead, I wanted to try so called _one-gadget_ shell. 

The great idea is calling **execve("/bin/sh")** with using only one address somewhere in **libc**. Simple to achive as long as we have the base address of libc. We are going to use a tool called _one_gadget_. Here's the github page for the tool and some reading: 
https://github.com/david942j/one_gadget  
https://book.hacktricks.xyz/binary-exploitation/rop-return-oriented-programing/ret2lib/one-gadget

![onegadget](https://github.com/user-attachments/assets/71eb2b96-2117-4d64-b21e-52072bd1bdab)

We have 3 options here, last `execve` call looks like the easiest to do. It has some constraints we need to fullfil. Not a big deal. But you need to create a **fake stack** so the calls in libc works (e.g `push, call...`). 

![flag](https://github.com/user-attachments/assets/3118cce8-ff3d-42e6-b8ff-1182a1e28ca5)

And we have a shell!



