## Description
None

## Category
#web 

## Hint
look at the status of our website (vishwactf.com/)...

## Solution
### Enumeration
Scrolling all the way down to the bottom of said website in the hint, we see a status check at bottom left.
![[Pasted image 20250305201527.png]]

This website reveals us 3 things:
1. A local:8080 is hosted but not reachable
2. A directory called /flag
3. Another website at the footer

![[Pasted image 20250305201629.png]]

At the time of writing, the said website is down. However:
1. The website has an URL input that is vulnerable to SSRF
2. Input MUST have http/https in the URL
3. the local/localhost doesn't work but 127.0.0.1:8000/flag works


![[Pasted image 20250305201742.png]]

