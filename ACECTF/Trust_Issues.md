## Description
![[Pasted image 20250228180854.png]]

## Category
#reverse
I first open the file with Ghidra since running `file` says it is a PE32 file, so it's worth checking the code first

## Solution
![[Pasted image 20250227163432.png]]

The decompiler reveals a main function with a string. But it seems like the string is not the password.
![[Pasted image 20250227163445.png]]

So I poke around till I stumble upon the _strcmp_ method is a custom one.

![[Pasted image 20250227163551.png]]

1. The code has a hardcoded array of bytes (`local_20`), which serves as an encryption key.

2. It's comparing each character of `_Str2` (which is "GRX14YcKLzXOlW5iaSlBIrN7") with each character of `_Str1` (the input) XORed with the corresponding byte from `local_20`.


This code 
```python
# Known comparison string
str2 = "GRX14YcKLzXOlW5iaSlBIrN7"

# XOR key from the local_20 array
xor_key = [0x06, 0x11, 0x1d, 0x72, 0x60, 0x1f, 0x18, 0x7c, 
           0x3e, 0x0f, 0x6d, 0x78, 0x33, 0x35, 0x40, 0x5e, 
           0x3e, 0x25, 0x5f, 0x30, 0x78, 0x14, 0x37, 0x4a]

# Calculate the password
password = ""
for i in range(len(str2)):
    if i < len(xor_key):
        # XOR each character with the corresponding key byte
        password += chr(ord(str2[i]) ^ xor_key[i])

print("Password to enter:", password)
```

Will perform the xor for us