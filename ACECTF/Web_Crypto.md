## Description
![[Pasted image 20250228181354.png]]

## Category
#web

## Solution
Accessing the site we see that it is actually a PHP code
![[Pasted image 20250227134610.png]]
This PHP asks for two param, tom and jerry. There value has to be different

This then compare the MD5 hash value when concatenate with ACECTF

Since this is using a double equal == It is vulnerable to magic hash attack
![[Pasted image 20250227134755.png]]

If we change this to array, the parameter stays the same as tom and jerry.

The only difference is PHP can't convert an array to a string, it only throws an error and only hashes the ACECTF string.

![[Pasted image 20250227134900.png]]