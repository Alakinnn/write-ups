## Dirb
```shell-session
alakin2504@htb[/htb]$ dirb http://<TARGET IP>:3002
```

## Param Fuzzing
```shell-session
alakin2504@htb[/htb]$ ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -u 'http://<TARGET IP>:3002/wsdl?FUZZ' -fs 0 -mc 200
```
