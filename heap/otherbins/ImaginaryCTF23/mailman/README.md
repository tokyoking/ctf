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

Challenge menu. Also this challenge has seccomp rules. 

```
local_20 = seccomp_init(0);
seccomp_rule_add(local_20, 0x7fff0000,2,0);
seccomp_rule_add(local_20, 0x7fff0000,0,0);
seccomp_rule_add(local_20, 0x7fff0000,1,0);
seccomp_rule_add(local_20, 0x7fff0000,5,0);
seccomp_rule_add(local_20, 0x7fff0000,0x3c,0);
seccomp_loead(local_20);
```

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
5 - ROP from saved rip of something using House of Botcake again
```

How to perform a House of Botcake attack? 

### House of Botcake

(Taken and edited from https://ret2school.github.io/post/mailman/,  https://surg.dev/ictf23/ and https://github.com/shellphish/how2heap/blob/master/glibc_2.35/house_of_botcake.c)

```
1-Allocate 7 0x100 sized chunks to then fill the tcache (7 entries).
2-Allocate two more 0x100 sized chunks (a previous chunk and victim chunk) 
3-Allocate a small “barrier” 0x10 sized chunk. (to prevent any further consolidation past our victim chunk)
4-Fill the tcache by freeing the first 7 chunks.
5-Free victum chunk, it ends up in the unsorted bin, since its too large for any other bin.
6-Free previous chunk, because malloc now sees two large, adjacent chunks, it consoldates them and places a 0x221 size block into the unsorted bin. (malloc automatically allocs 16 bytes more than what we ask, and uses the last byte as a flag, so this is the result of 2 0x110 chunks)
7-Request one more 0x100 sized chunk to let a single entry available in the tcache.
8-Free victim chunk again, this bypasses the naive double free exception, and since our victim chunk has the info for a 0x110 byte block, it gets placed into the tcache (uh oh).
9-That’s finished, to get a read what where we just need to request a 0x130 sized chunk (enough to overwrite the metadata of the next chunk). Thus we can hiijack the next fp of a that is currently referenced by the tcache by the location we wanna write to. And next time two 0x100 sized chunks are requested, first we'll get the victim chunk but then tcache will point to the target location.
```

We'll use this attack to leak a stack address by overwriting stdout's file structure with `environ`.

### File Structure

I'll cover this in detail when I started solving File Structure Exploits but for now this is all you need to know: 

```python
struct _IO_FILE
{
  int _flags;		/* High-order word is _IO_MAGIC; rest is flags. */

  /* The following pointers correspond to the C++ streambuf protocol. */
  char *_IO_read_ptr;	/* Current read pointer */
  char *_IO_read_end;	/* End of get area. */
  char *_IO_read_base;	/* Start of putback+get area. */
  char *_IO_write_base;	/* Start of put area. */
  char *_IO_write_ptr;	/* Current put pointer. */
  char *_IO_write_end;	/* End of put area. */
  char *_IO_buf_base;	/* Start of reserve area. */
  char *_IO_buf_end;	/* End of reserve area. */

  /* The following fields are used to support backing up and undo. */
  char *_IO_save_base; /* Pointer to start of non-current get area. */
  char *_IO_backup_base;  /* Pointer to first valid character of backup area */
  char *_IO_save_end; /* Pointer to end of non-current get area. */
```


If we set `char* _IO_read_end` and `char* _IO_write_base` the beginning of a memory that we want to write out and we set `char* _IO_write_ptr` to the end of that value and everything else to `NULL`, we will be able to leak out a value of our choosing.

