## Level: Medium

### Challenge
```
TLDR: use UAF to leak an address in unsorted bin arena, get allacotions on fastbin and perform a fastbin dup attack to overwrite __free_hook with system("/bin/sh")
```

![menu](https://github.com/user-attachments/assets/80649d50-4fe8-4ef2-b583-93bc2d9f9a58)

Challenge menu. 

![notecheck](https://github.com/user-attachments/assets/a9b4becb-f758-4ac1-b05a-4aae3e0b8a43)

Before we begin, there is a check for number of notes which is essentially how many times we can malloc. To get infitine number of allocations send a negative number when asked. 

### Checksec

![checksec](https://github.com/user-attachments/assets/d57bf470-07f8-406d-bad1-40f7bf3e4d62)

### Approach

```
1 - Fill a bin in tcache to get an allocation on unsorted bin
2 - UAF to leak the address in unsorted bin arena
```

We'll do this by allocating 8 chunks in a way that when free'd, 7 of them will go into the same tcache bin and the last one will go into unsorted bin. 

How do we know that we need 7 allocations? From the source code of glibc 2.31:

![7](https://github.com/user-attachments/assets/30db5d21-8b56-40fa-b0c2-0dfb3b1c1d13)

link: https://elixir.bootlin.com/glibc/glibc-2.31/source/malloc/malloc.c#L323

![unsorted](https://github.com/user-attachments/assets/fb594473-505b-48c9-a7db-30922bac2200)

Now we just need to leak it by simpy using `3. View notes` option with note id of our unsorted bin allocation. (UAF)

```
3 - Get allocations on fastbin by filling tcache sames size count again
4 - Do the double free trick in fastbin to get 2 malloc with same address
```
The reason we're doing this in fastbin instead of tcache is because we don't have a way to corrupt `key`, the double free protection mechanism in tcache. Fastbin doesn't have `key` protection and can be tricked to get a double free. 

```
  # The trick 
  free(a)
  free(b)
  free(a)
```



