## Description
None

## Category
#web 

## Solution
Note: This was a very, very, very confusing web exploitation. There's literally no exploitation in this problem. So feel free to skip.

### Enumeration
The website gives us a way to scan for URL. Meaning that it might be vulnerable to SSRF.
![[Pasted image 20250304212928.png]]

Which it is. However, this is NOT the solution.
![[Pasted image 20250304213028.png]]

Checking out the cookie gives us two other cookie, 1 is session and 1 is hint. The session can be used for impersonation. However, this is NOT the solution.

![[Pasted image 20250304213122.png]]

### Exploit
Create a webhook to see all requests information
![[Pasted image 20250304213157.png]]

Enter the webhook in the input
![[Pasted image 20250304213221.png]]

Comes the flag
![[Pasted image 20250304213227.png]]
