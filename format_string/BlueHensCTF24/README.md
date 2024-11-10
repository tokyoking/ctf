# Catagory: PWN
## Description
### Level: Easy

![desc](https://github.com/user-attachments/assets/b2559bb8-bd8c-47f7-a719-0ab7f67abdef)

## Approach

Running `checksec` on the chall!

![checks](https://github.com/user-attachments/assets/7a838479-0e3e-4a45-a0d3-c66c6de330a3)

## Running the binary

![binary](https://github.com/user-attachments/assets/a5287302-7a99-4deb-9b40-c8ccf748b1a1)

We see a cool menu, I played with the options for a few minutes then opened up the ghidra to see what's going on.

![ghdr](https://github.com/user-attachments/assets/e57e046e-d206-4db2-81f1-d7ae6c296792)

Looking at the decompiled main and the functions, we'll see that if we change the channel to 6 it'll prompt for a pin

![pinpop](https://github.com/user-attachments/assets/161f0d91-f11e-42ef-b930-b8451e5a18ff)
