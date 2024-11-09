# Catagory: PWN
## Description

![](https://github.com/user-attachments/assets/a173472b-22d7-4ca0-893e-8201c1c39ac7)

The challenge had 58 solves at the end of the ctf and it is worth 436 points!

## Approach
First we need to take a look at what is available for us with `checksec`. It'll give us a brief idea about the binary and what we are likely going to exploit.

![checksec](https://github.com/user-attachments/assets/56af64c3-db73-413b-8b7c-b12bc2d0068b)

No PIE, so it might be a buffer overflow but there is stack canary. Partial Relro, hmm, maybe we will overwrite a got table. Also not stripped, it will be easier to debug with the symbols. Nice, time to run the binary. 

## Running the binary

![loop](https://github.com/user-attachments/assets/5f00444d-a5e5-4f18-a086-e9f03020c309)

We see that it's keep asking for an input. Now looking at the binary in `gdb` with `gef` extension the _fork_ call immediately caught my attention. Looking at the end of **main** it calls **wait()** for a short delay then returns to **main+19** which is the **fork** call. So it loops with child processes and a __vuln__ function? hmm, _interesting_. 

![vulnandwin](https://github.com/user-attachments/assets/125ca499-37e0-4375-8131-bcbcebaed6df)

Looking the disassemble of **vuln**, there is **puts()** right after **read()** call. Chances are it's reading in our input then writing "Your data was read. Did you get the flag?" to stdout. And also there is probably a win function as in most challenges, so we checked for it. Great, we don't need a shell, we just need to call **win()**. But how do we do it? Canary is right there, we can't just overwrite. Or is it ever about overflowing the buffer? There is only way to check...

![stcksmh](https://github.com/user-attachments/assets/f29e13e6-5cce-40f3-904e-5404f6bedc4c)


And we get **stack smashing detected**. But wait, the binary didn't exit, only the child process terminated and it fork()ed again! How can we use this? What happens to the **stack canary** when the binary calls **fork()**? Stack canary is a secret value placed on the stack which changes everytime when the program is started, but because it's forking from parent process the stack canary _doesn't_ change! So that means the canary will stay the same as long as you don't hit `Ctrl+c` or terminate the program. Still, how can we use this information to overwrite the buffer to return to **win** from vuln? 

## Thinking about how to exploit and scripting in gdb

As in the challenge description "Note: using _brute-force_ methods on the challenge instance is permitted for this challenge." Can we guess the canary with brute-force? What happens if we overwrite only a byte into canary?  

![cantreach](https://github.com/user-attachments/assets/29628dd2-dd8c-4f6e-af5e-384c9ee0536b)

I set a breakpoint right after the call for **read()** to inspect the stack and find the offset to the canary but it didn't stop at our breakpoint... why?

![checkforchild](https://github.com/user-attachments/assets/e707b90f-e9e4-46b0-b1f9-c685b5d64cf3)

Because it checks for _process id_. A **child process** has process id of **0** therefore the child process will continue execution but the main process will jump to main+84 and wait for child to return. Then how can we redirect execution in a way that to call **vuln()** with the parent process and hit our breakpoint? With the power of **gdb** ofcourse! 

We have multiple options to bypass the check, we can set the value in **rbp-0x4** to **0** at checktime, or we can just change the next instruction. We can them manually but we'll probably run this binary a few times or we may accidentally hit a wrong button so writing a little gdb script is worth our time.  

![breakinvuln](https://github.com/user-attachments/assets/d21aa783-d8dd-46d6-be00-63547e1b9cad)

As you see we hit the breakpoint right after the **read()** call and if we inspect the stack with `x/20gx $rsp`:

![offset](https://github.com/user-attachments/assets/404f31ac-5ba3-4dce-91e8-324f298e918a)

We have our input at `0x7ffd41c76378` and the canary is at `0x7ffd41c763c0`. Most of the time the stack will look something like *canary* + *rbp* + *saved rip*. So the saved rip is at 16 bytes after the canary. Which you can confirm it with `info frame`. Good, now we need to calculate the offset from saved rip to start of our input. In gdb `p/d  0x7ffd41c763d0 - 0x7ffd41c76378` will show the offset in **decimal**. 

![offsetcalculate](https://github.com/user-attachments/assets/2988652c-e5af-4772-b864-96bd66575233)

Okay, now what? I want to overwrite 88 bytes after my buffer with the address of win but what about the canary? Let's do what we wanted to do earlier, overwrite only a byte into canary. Remember, saved rip is 16 bytes after canary. So the offset from our input to canary would be "72".

![rsp](https://github.com/user-attachments/assets/c10677e5-db70-4612-9768-cf1c7244e3e2)

We overwrite the least significant byte of the canary with "B", and when we continue execution the program received SIGABRT signal because we failed the canary check. But shouldn't it be in a loop? We smashed the stack earlier above in one of the screenshot but the program still ran? Yes and that is because we changed the _execution flow_ of the **parent process**. We SIGABRT with the parent process so it wasn't able to return from **vuln()** to **main** and call **fork()** again. As long as we don't play with the parent processs, it will keep asking for input even if it SIGABRTs from the canary check.  

Alright, what was the point of overwriting only a byte into canary again? Think about it. You are running in an infinite loop, and the program that tells you if the canary has corrupted. What if we sent a null byte instead of "B"? Will it SIGABRT again? No, because the canary has this security feature so its least significant byte will be always '\x00'. Okay then, what if we keep sending bytes and try to guess the canary? Oh wait.. what was the hint from the challenge description again? _brute-froce_.


# Your turn!
 Now we know everything to solve this challenge, guess the canary and call win! You should first try this yourself and see if you can write an exploit and get the flag. If you don't push yourself now, when&how will you learn? I'll add the binary and my solution, if you have any questions/problem or just to say thanks, message me on discord (@yanscat). Good luck hacker. 

Don't forget to create a "flag.txt" to test it locally.

![solved](https://github.com/user-attachments/assets/a4ad902d-973f-4cdb-a735-ffb27a8c42bf)

