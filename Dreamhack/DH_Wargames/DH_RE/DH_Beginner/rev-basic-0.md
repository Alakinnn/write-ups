![[Pasted image 20250214210224.png]]

I opened a file in Ghidra, taking a look at the functions till I come across this function that seems to take the user input
![[Pasted image 20250214210309.png]]

the FUN_140001000 seems to take the input somewhere before it gives either Wrong or Correct
That compares the user input with a predetermined string
![[Pasted image 20250214210345.png]]
Which is the flag.