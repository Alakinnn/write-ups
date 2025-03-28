#### Generating Rule-based Wordlist

```shell-session
alakin2504@htb[/htb]$ hashcat --force password.list -r custom.rule --stdout | sort -u > mut_password.list
alakin2504@htb[/htb]$ cat mut_password.list

password
Password
passw0rd
Passw0rd
```

Technically, this part is only about generating a specific password list then feed to hydra