## Level: Medium

### Challenge

My first heap challenge, thank you @p0ch1ta for this super cool challenge. The intended way is **House of Muney** which is *leaklesss* heap exploit but I cheese'd it with getting a **leak** :)
more about House of Muney: https://maxwelldulin.com/BlogPost/House-of-Muney-Heap-Exploitation

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

There are some caveats to fake a chunk and turns out `0x453510` is perfect. It's near got entries and most importantly mallocable. Be aware that you need to malloc 2 chunks with *enough size* to read into **free@got**. Which is at least `40 bytes` in this case. 

```
4 - Malloc twice so fake chunk gets allocated and points to free@got
```


