## Heap Exploitation Techniques


https://github.com/shellphish/how2heap and https://0x434b.dev/overview-of-glibc-heap-exploitation-techniques/ are awesome sites for heap exploit techniques. I made this list for quick reference to see if it's patched or not for certain glibc version. You should definetely check the original sites for more information about the techniques.

- Malloc hooks have been removed in GLIBC >= 2.34
- safe-linking mitigation in GLIBC >= 2.32
- tcache was introduced in GLIBC 2.26

### patched techniques
- House of Prime (Applicable until: < 2.4)
- Unsafe Unlink (Applicable until: < 2.3.4)
- House of Mind (Original) (Applicable until: < 2.11)
- House of Orange (Applicable until: < 2.26)
- House of Rabbit (Applicable until: < 2.28)
- Unsortedbin Attack (Applicable until: < 2.29)
- House of Force (Applicable until: < 2.29)
  -> Requirements
    1 - An overflow that allows to overwrite the size of the top chunk header (e.g. -1)
    2 - Be able to control the size of the heap allocation
- House of Corrosion (Applicable until: > 2.26 && < 2.30)
- House of Roman (Applicable until: < 2.29)
- House of Storm (Applicable until: < 2.29)
- House of Husk (Applicable until: < 2.29)
- House of Kauri (Applicable until: < 2.32)
- House of Fun (Applicable until: < 2.30)
- Tcache Dup (Applicable until: < 2.29)

### unpatched techniques 
- House of Lore (Applicable until: ?)
- Safe Unlink (Applicable until: ?)
- Fastbin Dup (Applicable until: ?)
- House of Spirit (Applicable until: ?)
- House of Einherjar (Applicable until: ?)
- House of Mind (Fastbin Edition) (Applicable until: ?)
- Poison NULL byte (Applicable until: ?)
- House of Muney (Applicable until: ?)
- House of Rust (Applicable until: ?)
- House of Crust (Applicable until: ?)
- House of IO (Applicable until: ?)
- Largebin attack (Applicable until: ?)
- Tcache - House of Botcake (Applicable until: > 2.25 && < ?)
- Tcache - House of Spirit (Applicable until: ?)
- Tcache - Poisoning (Applicable until: ?)
- Tcache - Stashing unlink (Applicable until: ?)
