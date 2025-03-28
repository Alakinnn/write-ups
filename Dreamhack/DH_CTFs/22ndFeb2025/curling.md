At the time of the attack, the website is being hosted on this
![[Pasted image 20250222080956.png]]

But no matter how many I try reconnecting, the same 404 occurs. I peek into the source code, to see 2 endpoints. 1 post and 1 get. The post only allow certain host and the get can only be used in a local network

![[Pasted image 20250222081111.png]]

So i first tested the SSRF with the local and the allowed host

![[Pasted image 20250222081243.png]]

so it seems like directly use the local network gives no result

i ask chatgpt where can I go next, it tell me that SSRF may be vunerable to redirection, subdomain spoofing and url filtering

What I mean is, if I enter exactly `/api/v1/test/internal`, it may not work. But if I HTML enconde the `/` with %252F, then it works.

![[Pasted image 20250222081654.png]]
