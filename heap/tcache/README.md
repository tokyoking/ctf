# Notes about glibc heap tcache

(https://pwn.college/software-exploitation/dynamic-allocator-misuse/)

most of the screenshots and code is from **pwncollege** slides and videos (mostly glibc 2.31). I made this to fresh up my knowledge about tcache before diving into heap ctfs.

allocations small then 1032 bytes = tcache

![tcacheglibcstruct](https://github.com/user-attachments/assets/cf1b98c1-79f2-4684-b173-3eeb80d22088)

(glibc-2.36)
source: https://elixir.bootlin.com/glibc/glibc-2.36/source/malloc/malloc.c#L3125

source: https://docs.google.com/presentation/d/13NbUlNvj1Rm-Cc_E_Crp678c-mgzCi0BYfzXIzFB3zI/edit?pli=1#slide=id.g47fd1f5b33_0_186

### Double Free
- `uintptr_t key` in `tcache_entry` is used for **double free** check.
If you corrupt the key and free a chunk twice, next two mallocs will return the same address.

![doublefree](https://github.com/user-attachments/assets/8c93b858-6d0b-4a2a-bd4e-6f2feb1d2558)


"Free the chunk, then use a UAF to overwrite chunk->key to any other value, and we will be able to free it again.

Free the chunk into one tcache bin, then change its size. You can immediately free it again and put it into a different tcache bin. You can then get the chunk back from the old tcache bin (prior to its size change) and immediately free it again due to the e->key field being nulled out. Now the new (second) tcache bin will have a double freed chunk in it."

"The other solution is based upon the fact that when you double free a chunk and cause a double free or corruption (fasttop) error, it will actually call malloc internally."

(from: https://faraz.faith/2019-10-12-picoctf-2019-heap-challs/#zero_to_hero, https://blog.osiris.cyber.nyu.edu/2017/09/30/csaw-ctf-2017-auir/)

### tcache poisoning
- on allocation `key` is cleared but `next` is not cleared. 
corrupt the next pointer of the last thing that was free()d.

                char stack_buffer[16];
                unsigned long long *a;
                unsigned long long *b;

                // warm up the tcache
                a = malloc(16);
                b = malloc(16);

                free(b);
                free(a);

                // corrupt the next pointer
                a[0] = &stack_buffer;

                printf("Stack buffer: %p\n", &stack_buffer);
                printf("First malloc: %p\n", malloc(16));
                printf("Second malloc: %p\n", malloc(16));

### chunks and metadata

![chunk](https://github.com/user-attachments/assets/5f6094c8-6730-46a6-be05-697ba2b3b3b2)

source: https://docs.google.com/presentation/d/1BlapIDslDaWeBPUamdG0i35-yveGvWJHZaW_0dan6sU/edit#slide=id.ga6f4d9d74e_1_0

![overlappingmetadat](https://github.com/user-attachments/assets/c48add04-ae38-4127-ba13-a9002f505532)

a snippet from Yan's video:

![overlapexample](https://github.com/user-attachments/assets/92f4de56-3b2c-4b44-8cd6-1286f7d1bc86)

### The Wilderness

a fake chunk at the end of the heap stores the available space which is called Wilderness



