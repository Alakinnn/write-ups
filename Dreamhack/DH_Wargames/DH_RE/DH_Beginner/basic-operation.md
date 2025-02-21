![[Pasted image 20250214220607.png]]
This code take in the user input at local_2c then perform a XOR with the random generated number in an integer form but printed as hex. 
The local_10 is the becomes a hex string at local_39
local_39 is the reverted to local_42
local_42 is compared with a certain string.

Which means that, to solve this, we need to revert the certain string so that is is equal to local_39. local_39 is basically local_10. We then perform XOR on local_10 and local_30 to find which local_2c we need. But since local_30 is in integer type, local_2c needs to be an integer