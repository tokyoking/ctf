## Level: Hard

### Challenge

```
TLDR: 
```

```
Welcome to the post office.
Enter your choice below:
1. Write a letter
2. Send a letter
3. Read a letter
>
```

Challenge menu.

`Write a letter` asks idx, letter size and content and allocates a chunk based on our input. `Send a letter` frees the chunk and `Read a letter` reads chunk's content.

![seccomp](https://github.com/user-attachments/assets/35868835-403b-4362-9a24-d88ccea336c0)

Seccomp implementation. 

### Checksec

```
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    RUNPATH:    b'.'
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

We can't overwrite got entries due to Full RELRO, can't use one_gadgets and other tricks like system("/bin/sh") due to seccomp restrictions so probably we need to ROP with ORW. 


