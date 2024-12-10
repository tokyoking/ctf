## Level: Medium

### Challenge
```
TLDR: use UAF to leak an address in unsorted bin arena, get allacotions on fastbin and perform a fastbin dup attack to overwrite __free_hook with system("/bin/sh")
```

### Checksec

![checksec](https://github.com/user-attachments/assets/d57bf470-07f8-406d-bad1-40f7bf3e4d62)

### Approach

```
1 - Fill a bin in tcache to get an allocation on fastbin
```

We'll do this by allocating 8 chunks in a way that when free'd, 7 of them will go into the same tcache bin and the last one will go into unsorted bin. 

How do we know that we need 7 allocations? From the source code of glibc 2.31:

![7](https://github.com/user-attachments/assets/b0fc031b-2041-4100-8d6f-4784e853edf6)



