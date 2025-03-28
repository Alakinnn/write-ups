
## Description
Feed my friend.
## Category
#reverse 

## Solution
Note: This challenge is extremely annoying as the given file is a PE32 file written in C++ 2006. Meaning that we need to get on environment older than Windows 8.

Reading the code, we can see that this is a snake game, and to get the flag, you need 9999 score. Meaning we can simply change the required score to 1 or 0 (I didn't change to 0 with fear that it would break the game)

![[Pasted image 20250304170739.png]]

Another important thing to add is that the imported DLLs file in the original code weren't there, so I manually added them.

![[Pasted image 20250304170820.png]]
![[Pasted image 20250304170844.png]]

So when I launch the application on Windows 7, for any DLL files that are missing. Download them on the internet with architecture = 32 bit.

Playing the game gives the flag
![[Pasted image 20250304171008.png]]

