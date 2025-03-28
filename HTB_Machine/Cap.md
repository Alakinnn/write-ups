I scanned the IP to see there are 3 services
![[Pasted image 20250223133634.png]]

Visiting this endpoint, I tried to see if the param is vulnerable to IDOR
![[Pasted image 20250223133908.png]]
![[Pasted image 20250223133744.png]]

I found a specific number that leads to vulnerable file, pcap.

a pcap file reveal some credentials
![[Pasted image 20250223133950.png]]

I reuse the same credentials for SSH service which works and gave me the first flag
and then perform linux priv esc https://gtfobins.github.io/gtfobins/python/?source=post_page-----eb9c97f2259c---------------------------------------#capabilities

![[Pasted image 20250223134056.png]]
