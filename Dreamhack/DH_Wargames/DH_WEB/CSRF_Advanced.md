![[Pasted image 20250303125207.png]]

The login logic reveals that a csfr token is generated with the username and the remote_addr. Meaning that this token will be fixed no matter what

![[Pasted image 20250303125302.png]]

This token is used in this path where it requires a password param and the csrftoken

Therefore, we can craft a payload like this `<img src="/change_password?pw=123&csrftoken=7505b9c72ab4aa94b1a4ed7b207b67fb"></img>`

and feed to the
![[Pasted image 20250303125409.png]]

![[Pasted image 20250303125419.png]]
