# Catagory: PWN
## Description

![](https://github.com/user-attachments/assets/a173472b-22d7-4ca0-893e-8201c1c39ac7)

The challenge had 58 solves at the end of the ctf and it is worth 436 points!

# Approach
First we need to take a look at what is available for us with `checksec`. It gives us an roughly idea about the binary.

![checksec](https://github.com/user-attachments/assets/56af64c3-db73-413b-8b7c-b12bc2d0068b)

No PIE, so it might be a buffer overflow but there is stack canary. Partial Relro, hmm, maybe we will overwrite a got table. Also no strips, it will be easier to debug with the symbols. Okay, time to run the binary. 

# Running the binary



![loop](https://github.com/user-attachments/assets/5f00444d-a5e5-4f18-a086-e9f03020c309)

We see that it's keep asking for an input. Now looking at the binary in `gdb` with `gef` extension the _fork_ call immediately caught my attention. Looking at the end of **main** it calls **wait** for a short delay then returns to **main+19** which is the **fork** call. So it loops with child processes. Hmm, _interesting_. 
