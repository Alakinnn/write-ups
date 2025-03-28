## Enumeration
Checking available endpoints/apis to see which one carries parameter

*Search Bar* seems to rerender only
![[Pasted image 20250307145728.png]]

*Advanced Search* ![[Pasted image 20250307145800.png]]

I found the move api seems to check for command injection![[Pasted image 20250307145906.png]]

The ampersand payload works
![[Pasted image 20250307145928.png]]

## Exploitation
But the problem is the file is missing, meaning we have limited tries.
![[Pasted image 20250307150032.png]]

Seems like whoami is filtered
The payload works but the file is not moved, seems like the payload is not meant to be there
![[Pasted image 20250307150225.png]]
Changing the location works
![[Pasted image 20250307150246.png]]

This payload is a dir ../../../
![[Pasted image 20250307150322.png]]

Now we only need to cat the flag and done!
