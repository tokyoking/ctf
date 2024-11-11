# Catagory: PWN
## Description
### Level: Easy

![rev](https://github.com/user-attachments/assets/622e82e4-df37-4565-9036-42abf4e692b9)

It is the same challenge as shellcode_runner3 but with a revenge! The previous challenge didn't restrict `int 0x80` due to some compile issue so `int 0x80` was an unintended solution (what i've heard from Discord). In this revenge version, both `int 0x80` and `syscall` filtered out. 

## Approach

