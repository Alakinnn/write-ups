[[CBBH_Verb_Tampering]]
[[CBBH_IDOR]]
[[CBBH_XXE]]

## Skills Assessment
## Enumeration
After logging in, we have these available APIs with the account:
http://94.237.54.190:46140/profile.php
http://94.237.54.190:46140/settings.php
http://94.237.54.190:46140/reset.php

what stand out among these are `profile.php` and `reset.php`

Enumerating profile.php may help us locate an admin user and IDOR
Enumerating reset.php may help us change the password of admin user with HTTP verb and IDOR


We can see that everytime we fetch the profile.php, it calls this API
![[Pasted image 20250317200851.png]]

Using intruder, we see that user id 52 is the admin
![[Pasted image 20250317201009.png]]
We also see here that whenever we change the password, the payloads has the uid, a csrf token and the changed password
![[Pasted image 20250317201116.png]]
If we simply change the uid, we get access denied
![[Pasted image 20250317201143.png]]
If we change to GET, it says invalid token
![[Pasted image 20250317201220.png]]
If we look at Burp again, there's an API that changes the token based on UID
![[Pasted image 20250317201258.png]]
![[Pasted image 20250317201407.png]]
We have successfully change the password
![[Pasted image 20250317201427.png]]
After logging in as admin, we see they have an API to create event
And the payload looks like it is vulnerable to XXE
![[Pasted image 20250317201621.png]]
And indeed it is
![[Pasted image 20250317201705.png]]
![[Pasted image 20250317201734.png]]
![[Pasted image 20250317201743.png]]
