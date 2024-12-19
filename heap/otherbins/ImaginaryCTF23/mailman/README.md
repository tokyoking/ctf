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

Looks like instead of getting a shell we'll just read the flag with allowed ORW syscalls. 
