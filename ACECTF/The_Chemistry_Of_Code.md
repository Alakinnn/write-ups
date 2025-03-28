## Description
![[Pasted image 20250228180544.png]]

## Category
#reverse

## Solution
Extracting the file, we see a rust file.
![[Pasted image 20250228023323.png]]
There is a password and a secret with the latter is more likely to be a flag since the password is a base64 string.

Decoding the password gives us a hex string, the 'e' is a giveaway.
![[Pasted image 20250228023416.png]]

Decoding Hex to ASCII is possible, so we might use that.
![[Pasted image 20250228023436.png]]

When we run the rust file, it asks for a catalyst and a reagent, similar to username/password.

![[Pasted image 20250228023445.png]]

