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

Seccomp rules.  

## Approach

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

So we can't overwrite got entries due to Full RELRO, can't use one_gadgets and other tricks like system("/bin/sh") due to seccomp restrictions. ORW syscall are allowed tho, and we can write out the flag if we can get a stack leak and ROP from there.. Also one more thing to consider, safe-linking is enabled but shouldn't be a big deal. 

### Safe-Linking

source: https://elixir.bootlin.com/glibc/glibc-2.35/source/malloc/malloc.c#L349

```
/* Safe-Linking:
   Use randomness from ASLR (mmap_base) to protect single-linked lists
   of Fast-Bins and TCache.  That is, mask the "next" pointers of the
   lists' chunks, and also perform allocation alignment checks on them.
   This mechanism reduces the risk of pointer hijacking, as was done with
   Safe-Unlinking in the double-linked lists of Small-Bins.
   It assumes a minimum page size of 4096 bytes (12 bits).  Systems with
   larger pages provide less entropy, although the pointer mangling
   still works.  */
#define PROTECT_PTR(pos, ptr) \
  ((__typeof (ptr)) ((((size_t) pos) >> 12) ^ ((size_t) ptr)))
#define REVEAL_PTR(ptr)  PROTECT_PTR (&ptr, ptr)
```

Basically tcache and fastbins next pointers are mangled to prevent classic heap attacks. So when we leak an address via UAF, it's going to be mangled in glibc 2.35 and higher. This just makes it harder to exploit, but its still exploitable. We can demangle the mangled pointer with this simple demangle function:

```
def demangle(ptr):
    mid = ptr ^ (ptr >> 12)
    return mid ^ (mid >> 24)
```
If you want to learn how this works, I'd recommend watching pwncollege's safe-linking video in dynamic allocation exploit module. 

Okay so our approach should be like this:

```
1 - Leak mangled next pointer of a chunk via UAF and demangle it to get the demangled next pointer
2 - Leak the libc address in unsorted bin
3 - Perform House of Botcake attack to get read-what-where
4 - Leak environ's stack address with changing stdout file struct via House of Botcake
5 - ROP from saved rip of something 
```







