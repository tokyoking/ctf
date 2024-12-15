## Level: Medium

  TLDR: create a chunk and overwrite the wilderness with a very large number due to overflow. This will overlap the target address and resulting in write-what-where, which you can use it to overwrite malloc_hook with system to get a shell.  
  
### Checksec

![checksec](https://github.com/user-attachments/assets/b1f5f164-7791-4db8-80d0-da2e3aeca2af)

### Challenge
  
![menu](https://github.com/user-attachments/assets/24c5f22c-227d-488b-9446-7efe84d7e67e)

Very cool menu :D

We have an overflow in `[3] Call an emergency meeting` so we can create a chunk then overwrite the wilderness (the top chunk's size) with a very large number (e.g. -1). This will make sure that malloc won't use `mmap` for any further allocations because it will think the top chunk has always enough space. And this will reuslt in overlapping target address. 
