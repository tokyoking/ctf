# Catagory: PWN
## Description

![](https://github.com/user-attachments/assets/a173472b-22d7-4ca0-893e-8201c1c39ac7)

The challenge had 58 solves at the end of the ctf and it is worth 436 points!

# Approach
First we need to take a look at what is available for us with `checksec`. It gives us roughly an idea about the binary.

![checksec](https://github.com/user-attachments/assets/56af64c3-db73-413b-8b7c-b12bc2d0068b)

No PIE, so it might be a buffer overflow but there is stack canary. Partial Relro, hmm, maybe we will overwrite a got table.


