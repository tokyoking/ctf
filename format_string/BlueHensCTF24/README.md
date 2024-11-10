# Catagory: PWN
## Description
### Level: Easy

![desc](https://github.com/user-attachments/assets/b2559bb8-bd8c-47f7-a719-0ab7f67abdef)

## Approach

Running `checksec` on the chall!

![checks](https://github.com/user-attachments/assets/7a838479-0e3e-4a45-a0d3-c66c6de330a3)

## Running the binary

![binary](https://github.com/user-attachments/assets/a5287302-7a99-4deb-9b40-c8ccf748b1a1)

We see a cool menu, I played with the options for a few minutes then opened up ghidra to see what's going on.

![ghdr](https://github.com/user-attachments/assets/e57e046e-d206-4db2-81f1-d7ae6c296792)

Looking at the decompiled main and the functions, we'll see that if we change the channel to 6 it'll prompt for a pin.

![pinpop](https://github.com/user-attachments/assets/161f0d91-f11e-42ef-b930-b8451e5a18ff)

And it pops up how many tries left. Cool. 

![fmt](https://github.com/user-attachments/assets/2c3b6047-0962-43f6-b5e7-c2ef1442f4c1)

Back with Ghidra again, and looking at the **programming mode** option, it's getting our input from stdin with **fgets()** then printing back to us with **printf()** but without specifying the format. If you don't know about what is format string, and how to exploit it you should check these cool writeups:

https://vickieli.dev/binary%20exploitation/format-string-vulnerabilities/
https://codearcana.com/posts/2013/05/02/introduction-to-format-string-exploits.html
https://axcheron.github.io/exploit-101-format-strings/

![leak2](https://github.com/user-attachments/assets/d627aafb-9316-462c-a2ba-5112585db671)

Woah! We leaked bunch of stuff. What else we can use instead of `%lx`? I'll try speedrun a few things.  

`%lx` leaks 8 bytes                `%7$x` prints the 7th parameter (on the stack)
`%x` leaks 4 bytes                 `%s` dereferences a pointer and reads it until null byte
`%hx` leaks 2 bytes                `%n` dereferences a pointer from the stack and write the number of bytes 'displayed' so far to it 
`%hhx` leaks only a byte           `%9c%10$hhn` writes '9' to the dereferenced address of the tenth parameter on the stack 

Alright, cool. Let's check what we leaked on the stack with gdb.

![stacke](https://github.com/user-attachments/assets/fb5cafef-8950-42bf-bca5-b6b459ee4c07)

Okay, if you remember, the challenge was asking for a pin and calling **checkPin()**. Let's disassemble it.

![pincheck](https://github.com/user-attachments/assets/73a7d3e3-7a5c-4339-ac6e-048cb4ae8a68)

We see that its dereferencing a lot from rax to rax, then comparing with rdx, which is probably our input. 

![pinaddr](https://github.com/user-attachments/assets/31a216d4-2c91-423f-bd84-58e11406ea95)

In ghidra, we see that **pin** is set here in **main()**, and if we look at the **checkPin** again

![***pin](https://github.com/user-attachments/assets/a512a286-4a59-4bbe-b440-4f20d960adbc)

It is dereferencing a lot but there isn't enough derefences to get *0x420* into **rax**. So its end up comparing an address with out input.

![compare](https://github.com/user-attachments/assets/82ccace0-317a-4ecf-a788-76c87b9a0a9d)

We can use **%n** in a way so it zero outs **rax** to pass the check but do we know the offset for %n? Yes, if we look at our leak: (I accidentally nuked the previous gdb, so all the offset is gone. Don't look back to `%lx` output I did before)

![leak4](https://github.com/user-attachments/assets/5ecbab13-cf3b-474c-80ad-63cc71395367)

It is the 12th `%lx` so we need to use `%12$nn` to write into the dereferenced address of the 12th parameter on the stack. If you look at the stack I posted eariler, and count it to the address that we want to use `%n` on, you'll see that it is not the 12th but the 18th parameter! Because printf uses rdi, rsi, rdx, rcx, r8 and r9 to hold the address and the format string! If it's not enough to hold all the format strings, it uses the stack. So, if you're looking for offsets in gdb, don't forget to substract "6". 

![wover](https://github.com/user-attachments/assets/1fc7f201-afa0-4053-94c4-fb6853cb7f3e)

And we succesfully overwrite it with "0"!

![flag](https://github.com/user-attachments/assets/933b5016-1184-449f-9196-4dad7572da95)













