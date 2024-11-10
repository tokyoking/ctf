# Catagory: PWN
## Description
### Level: Easy

![descriptoon](https://github.com/user-attachments/assets/340cad2d-56ad-4d30-95a4-044895d56838)

## Approach

Even if we know this is a shellcode challenge from the description, it's still important to check the properties of the binary.

![chkcsec](https://github.com/user-attachments/assets/eee19196-3b70-4c93-a55a-35598c351996)

No stripped, rest is up. No good :*

## Running the binary

![runbinary](https://github.com/user-attachments/assets/0c5dc3b7-09f7-4603-ae42-309ed8e725c1)

It asks for shellcode, very straigthforward.

If you disassemble main, you'll see a call for **blacklist** function. As the name suggest our shellcode getting filtered.

![blckisr](https://github.com/user-attachments/assets/cc547734-8802-45fa-ae08-964176407fcc)




