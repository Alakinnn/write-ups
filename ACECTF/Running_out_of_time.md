## Description
![[Pasted image 20250228182140.png]]
## Category
#binary
## Solution

The obvious thing to do when I see an elf file is to check out in Ghidra. I find a main function comparing the string with a local_c value, if corrects it calls a function.
![[Pasted image 20250228021923.png]]

So I check what that function does:
![[Pasted image 20250228021933.png]]

The loop performs a XOR operation for each character in the local_28 array
So technically, this problem is solved by understanding the output encryption and not even the input sanitization.

Which is literally the flag.