[[CBBH_SS_SSRF]]
[[CBBH_SS_STI]]
[[CBBH_SS_SSI]]
[[CBBH_SS_XSLTi]]

# Skills Assessment
## Enum
We found a script on the main page
![[Pasted image 20250315185330.png]]

This payload fetches the web app with the internal API, which confirms it is vulnerable to SSRF
![[Pasted image 20250315185501.png]]
Since the api has an id param, we want to see if it is vulnerable to STI.
![[Pasted image 20250315185557.png]]

## Exploit
After poking around the param, we know that it doesn't allow `space` in its id
![[Pasted image 20250315185701.png]]

It also can't be used with URL encode. But since it's Twig, we know that it might be a linux environment, so testing with the `${IFS}` doesn't hurt.

![[Pasted image 20250315185804.png]]
