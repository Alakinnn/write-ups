## Description
![[Pasted image 20250228182108.png]]
## Category
#binary
## Solution
`strings` gives nothing useful so I use `Ghidra` instead

![[Pasted image 20250227230048.png]]

the redirect_to_success is the function that calls the flag
![[Pasted image 20250227230114.png]]

so this problem seems to want to give it the address to the redirect_to_success method.

![[Pasted image 20250227230209.png]]
main address is dynamic but one thing static is the difference between two address

![[Pasted image 20250227230246.png]]

Gives 0xB9

so it means when it runs, i just need to add that
![[Pasted image 20250227230352.png]]
