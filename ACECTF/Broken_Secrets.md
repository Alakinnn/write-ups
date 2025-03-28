
## Description

![[Pasted image 20250228175514.png]]

## Category
#forensics
## Solution
Unarchiving brokenfr many times gives a folder.
![[Pasted image 20250228012054.png]]

Digging a little leads to this file
![[Pasted image 20250228012257.png]]

When we check for binary and strings, we can see that the file has an IHDR, indicating that it is a PNG file.
![[Pasted image 20250228012320.png]]

The first 8 bytes are broken, in the image, they are already fixed. Originally, they were 0s.
![[Pasted image 20250228012337.png]]

Fixing the bytes gives us the flag.
![[Pasted image 20250228012356.png]]\
