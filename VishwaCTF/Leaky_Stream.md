## Description
In the middle of our conversation, some packets went amiss. We managed to resend a few but they were slightly altered.  
Help me reconstruct the message and I'll reward you with something useful ;)

## Category
#forensics 

## Solution
We have a pcap file. Since it was a conversation, packets went missing and resend ability. We can be almost certain that we are dealing with TCP.

It is kinda laboursome, we have to check every resent packet, colored in black
![[Pasted image 20250304213547.png]]
We found a frame that has a comment

![[Pasted image 20250304213609.png]]

Therefore, we can expect that, the other packet also has a commet
![[Pasted image 20250304213732.png]]
