## Level: Medium

    TLDR: create a chunk and overwrite the wilderness with a very large number due to overflow. This will overlap the target address and resulting in write-what-where, which you can use it to overwrite malloc_hook with system to get a shell.  
  
### Checksec

![checksec](https://github.com/user-attachments/assets/b1f5f164-7791-4db8-80d0-da2e3aeca2af)

### Challenge
  
![menu](https://github.com/user-attachments/assets/24c5f22c-227d-488b-9446-7efe84d7e67e)

Very cool menu :D
We have a heap and a libc leak (option 2).

We have an overflow in `[3] Call an emergency meeting` so we can create a chunk then overwrite the wilderness (the top chunk's size) with a very large number (e.g. -1). This will make sure that malloc won't use `mmap` for any further allocations because it will think the top chunk has always enough space. And this will result in overlapping target address (write-what-where). 

### Approach 

```
1 - Use the overflow in `[3] Call an emergency meeting` to overwrite the wilderness with a very large number.
```

![newwilderness](https://github.com/user-attachments/assets/47fb63ae-68a5-46e8-b76c-bf89da5d1922)

```
2 - Calculate the address of wilderness and the target from the leaks
3 - Allocate a chunk with size of target - top_addr - 0x10 # for metadata
```

![overlapsize](https://github.com/user-attachments/assets/2cb9e4e7-8221-4398-a75d-f3bbffa74f19)


```
4 - Overwrite malloc_hook pointer (the target address) with system
```

![systemoverwrite](https://github.com/user-attachments/assets/f5518ba2-59f8-4808-99ed-6df30c7f0f5e)

```
5 - Call malloc with the address of "/bin/sh" as size to get a shell
```

![flag](https://github.com/user-attachments/assets/bc4a5ea9-72a6-487b-88b8-03b28a7dc0ef)
