## Common Hash Types

During penetration test engagements, we encounter a wide variety of hash types; some are extremely common and seen on most engagements, while others are seen very rarely or not at all. As stated previously, the creators of `Hashcat` maintain a list of [example hashes](https://hashcat.net/wiki/doku.php?id=example_hashes) most hash modes that `Hashcat` supports. The list includes the hash mode, hash name, and a sample hash of the specified type. Some of the most commonly seen hashes are

|Hashmode|Hash Name|Example Hash|
|---|---|---|
|0|MD5|8743b52063cd84097a65d1633f5c74f5|
|100|SHA1|b89eaac7e61417341b710b727768294d0e6a277b|
|1000|NTLM|b4b9b02e6f09a9bd760f388b67351e2b|
|1800|sha512crypt $6$, SHA512 (Unix)|$6$52450745$k5ka2p8bFuSmoVT1tzOyyuaREkkKBcCNqoDKzYiJL9RaE8yMnPgh2XzzF0NDrUhgrcLwg78xs1w5pJiypEdFX/|
|3200|bcrypt $2*$, Blowfish (Unix)|$2a$05$LhayLxezLhK1LhWvKxCyLOj0j1u.Kj0jZ0pEmm134uzrQlFvQJLF6|
|5500|NetNTLMv1 / NetNTLMv1+ESS|u4-netntlm::kNS:338d08f8e26de93300000000000000000000000000000000:9526fb8c23a90751cdd619b6cea564742e1e4bf33006ba41:cb8086049ec4736c|
|5600|NetNTLMv2|admin::N46iSNekpT:08ca45b7d7ea58ee:88dcbe4446168966a153a0064958dac6:5c7830315c7830310000000000000b45c67103d07d7b95acd12ffa11230e0000000052920b85f78d013c31cdb3b92f5d765c783030|
|13100|Kerberos 5 TGS-REP etype 23|$krb5tgs$23$_user$realm$test/spn_$63386d22d359fe42230300d56852c9eb$ < SNIP >|

---

## Example 1 - Database Dumps

MD5, SHA1, and bcrypt hashes are often seen in database dumps. These hashes may be retrieved following a successful SQL injection attack or found in publicly available password data breach database dumps. MD5 and SHA1 are typically easier to crack than bcrypt, which may have many rounds of the Blowfish algorithm applied.

Let's crack some SHA1 hashes. Take the following list:

#### SHA1 Hashes List

  Cracking Common Hashes

```shell-session
winter!
baseball1
waterslide
summertime
baconandeggs
beach1234
sunshine1
welcome1
password123
```

We can create a SHA1 of each word quickly:

#### Generate SHA1 Hashes

  Cracking Common Hashes

```shell-session
alakin2504@htb[/htb]$ for i in $(cat words); do echo -n $i | sha1sum | tr -d ' -';done

fa3c9ecfc251824df74026b4f40e4b373fd4fc46
e6852777c0260493de41fb43918ab07bbb3a659c
0c3feaa16f73493f998970e22b2a02cb9b546768
b863c49eada14e3a8816220a7ab7054c28693664
b0feedd70a346f7f75086026169825996d7196f9
f47f832cba913ec305b07958b41babe2e0ad0437
08b314f0e1e2c41ec92c3735910658e5a82c6ba7
e35bece6c5e6e0e86ca51d0440e92282a9d6ac8a
cbfdac6008f9cab4083784cbd1874f76618d2a97
```

We can then run these through a `Hashcat` dictionary attack using the `rockyou.txt` wordlist.

  Cracking Common Hashes

```shell-session
alakin2504@htb[/htb]$ hashcat -m 100 SHA1_hashes /opt/useful/seclists/Passwords/Leaked-Databases/rockyou.txt

hashcat (v6.1.1) starting...
<SNIP>

08b314f0e1e2c41ec92c3735910658e5a82c6ba7:sunshine1
e35bece6c5e6e0e86ca51d0440e92282a9d6ac8a:welcome1
e6852777c0260493de41fb43918ab07bbb3a659c:baseball1
b863c49eada14e3a8816220a7ab7054c28693664:summertime
fa3c9ecfc251824df74026b4f40e4b373fd4fc46:winter! 
b0feedd70a346f7f75086026169825996d7196f9:baconandeggs
f47f832cba913ec305b07958b41babe2e0ad0437:beach1234
0c3feaa16f73493f998970e22b2a02cb9b546768:waterslide
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: SHA1
Hash.Target......: SHA1_hashes
Time.Started.....: Fri Aug 28 22:22:56 2020, (1 sec)
Time.Estimated...: Fri Aug 28 22:22:57 2020, (0 secs)
Guess.Base.......: File (/opt/useful/seclists/Passwords/Leaked-Databases/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  2790.2 kH/s (0.33ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 9/9 (100.00%) Digests
Progress.........: 1173504/14344385 (8.18%)
Rejected.........: 0/1173504 (0.00%)
Restore.Point....: 1167360/14344385 (8.14%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: whitenerdy -> warut69
```

The above hashes cracked very quickly as they are common words/phrases with little to no complexity. Variations on the above list, such as "`Bas3b@ll1`" or "`Wat3rSl1de`" would likely take longer to crack and may require additional techniques such as mask and hybrid attacks.

## Example 2 - Linux Shadow File

Sha512crypt hashes are commonly found in the `/etc/shadow` file on Linux systems. This file contains the password hashes for all accounts with a login shell assigned to them. We may gain access to a Linux system during a penetration test via a web application attack or successful exploitation of a vulnerable service. We may exploit a service that is already running in the context of the highest privileged `root` account and perform a successful privilege escalation attack and access the `/etc/shadow` file. Password re-use is widespread. A cracked password may give us access to other servers, network devices, or even be used as a foothold into a target's Active Directory environment.

Let's look at a hash from a standard Ubuntu installation. The corresponding plaintext for the following hash is "`password123`".

#### Root Password in Ubuntu Linux

```shell-session
root:$6$tOA0cyybhb/Hr7DN$htr2vffCWiPGnyFOicJiXJVMbk1muPORR.eRGYfBYUnNPUjWABGPFiphjIjJC5xPfFUASIbVKDAHS3vTW1qU.1:18285:0:99999:7:::
```

The hash contains nine fields separated by colons. The first two fields contain the username and its encrypted hash. The rest of the fields contain various attributes such as password creation time, last change time, and expiry.

Coming to the hash, we already know that it contains three fields delimited by "`$`". The value "`6`" stands for the SHA-512 hashing algorithm; the next 16 characters represent the salt, while the rest of it is the actual hash.

Let's crack this hash using `Hashcat`.

  Cracking Common Hashes

```shell-session
alakin2504@htb[/htb]$ hashcat -m 1800 nix_hash /opt/useful/seclists/Passwords/Leaked-Databases/rockyou.txt

hashcat (v6.1.1) starting...
<SNIP>

$6$tOA0cyybhb/Hr7DN$htr2vffCWiPGnyFOicJiXJVMbk1muPORR.eRGYfBYUnNPUjWABGPFiphjIjJC5xPfFUASIbVKDAHS3vTW1qU.1:password123
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: sha512crypt $6$, SHA512 (Unix)
Hash.Target......: $6$tOA0cyybhb/Hr7DN$htr2vffCWiPGnyFOicJiXJVMbk1muPO...W1qU.1
Time.Started.....: Fri Aug 28 22:25:26 2020, (1 sec)
Time.Estimated...: Fri Aug 28 22:25:27 2020, (0 secs)
Guess.Base.......: File (/opt/useful/seclists/Passwords/Leaked-Databases/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:      955 H/s (4.62ms) @ Accel:32 Loops:256 Thr:1 Vec:4
Recovered........: 1/1 (100.00%) Digests
Progress.........: 1536/14344385 (0.01%)
Rejected.........: 0/1536 (0.00%)
Restore.Point....: 1344/14344385 (0.01%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:4864-5000
Candidates.#1....: teacher -> mexico1
```

---

## Example 3 - Common Active Directory Password Hash Types

Credential theft and password re-use are widespread tactics during assessments against organizations using Active Directory to manage their environment. It is often possible to obtain credentials in cleartext or re-use password hashes to further access via Pass-the-Hash or SMB Relay attacks. Still, some techniques will result in a password hash that must be cracked offline to further our access. Some examples include a NetNTLMv1 or NetNTLMv2 obtained through a Man-in-the-middle (MITM) attack, a Kerberos 5 TGS-REP hash obtained through a Kerberoasting attack, or an NTLM hash obtained either by dumping credentials from memory using the `Mimikatz` tool or obtained from a Windows machine's local SAM database.

---

#### NTLM

One example is retrieving an NTLM password hash for a user that has Remote Desktop (RDP) access to a server but is not a local administrator, so the NTLM hash cannot be used for a pass-the-hash attack to gain access. In this case, the cleartext password is necessary to further our access by connecting to the server via RDP and performing further enumeration within the network or looking for local privilege escalation vectors.

Let's walk through an example. We can quickly generate an NTLM hash of the password "`Password01`" for our purposes using 3 lines of Python:

#### Python3 - Hashlib

  Cracking Common Hashes

```shell-session
alakin2504@htb[/htb]$ python3

Python 3.8.3 (default, May 14 2020, 11:03:12) 
[GCC 9.3.0] on linux
Type "help", "copyright", "credits" or "license" for more information.

>>> import hashlib,binascii
>>> hash = hashlib.new('md4', "Password01".encode('utf-16le')).digest()
>>> print (binascii.hexlify(hash))

b'7100a909c7ff05b266af3c42ec058c33'
```

We can then run the resultant NTLM password hash value "`7100a909c7ff05b266af3c42ec058c33`" through `Hashcat` using the standard `rockyou.txt` wordlist to retrieve the cleartext.

#### Hashcat - Cracking NTLM Hashes

  Cracking Common Hashes

```shell-session
alakin2504@htb[/htb]$ hashcat -a 0 -m 1000 ntlm_example /opt/useful/seclists/Passwords/Leaked-Databases/rockyou.txt

hashcat (v6.1.1) starting...
<SNIP>

7100a909c7ff05b266af3c42ec058c33:Password01      
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: NTLM
Hash.Target......: 7100a909c7ff05b266af3c42ec058c33
Time.Started.....: Fri Aug 28 22:27:40 2020, (0 secs)
Time.Estimated...: Fri Aug 28 22:27:40 2020, (0 secs)
Guess.Base.......: File (/opt/useful/seclists/Passwords/Leaked-Databases/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  2110.5 kH/s (0.62ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 61440/14344385 (0.43%)
Rejected.........: 0/61440 (0.00%)
Restore.Point....: 55296/14344385 (0.39%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: gonoles -> sinead1
```

Now, armed with the cleartext password, we can further our access within the network.

---

#### NetNTLMv2

During a penetration test it is common to run tools such as [Responder](https://github.com/lgandx/Responder) to perform MITM attacks to attempt to "steal" credentials. These types of attacks are covered in-depth in other modules. In busy corporate networks it is common to retrieve many NetNTLMv2 password hashes using this method. These can often be cracked and leveraged to establish a foothold in the Active Directory environment or sometimes even gain full administrative access to many or all systems depending on the privileges granted to the user account associated with the password hash. Consider the password hash below retrieved using `Responder` at the beginning of an assessment:

#### Responder - NTLMv2

  Cracking Common Hashes

```shell-session
sqladmin::INLANEFREIGHT:f54d6f198a7a47d4:7FECABAE13101DAAA20F1B09F7F7A4EA:0101000000000000C0653150DE09D20126F3F71DF13C1FD8000000000200080053004D004200330001001E00570049004E002D00500052004800340039003200520051004100460056000400140053004D00420033002E006C006F00630061006C0003003400570049004E002D00500052004800340039003200520051004100460056002E0053004D00420033002E006C006F00630061006C000500140053004D00420033002E006C006F00630061006C0007000800C0653150DE09D201060004000200000008003000300000000000000000000000003000001A67637962F2B7BF297745E6074934196D5F4371B6BA3E796F2997306FD4C1C00A001000000000000000000000000000000000000900280063006900660073002F003100390032002E003100360038002E003100390035002E00310037003000000000000000000000000000
```

Some tools, such as `Responder`, will inform you what type of hash was received. We can also check the [Example hashes](https://hashcat.net/wiki/doku.php?id=example_hashes) page if in doubt and confirm that this is indeed a NetNTLMv2 hash, or mode `5600` in `Hashcat`.

As with the previous examples, we can run this hash with `Hashcat` using the `rockyou.txt` wordlist to perform an offline dictionary attack.

#### Hashcat - Cracking NTLMv2 Hashes

  Cracking Common Hashes

```shell-session
alakin2504@htb[/htb]$ hashcat -a 0 -m 5600 inlanefreight_ntlmv2 /opt/useful/seclists/Passwords/Leaked-Databases/rockyou.txt

hashcat (v6.1.1) starting...
<SNIP>

SQLADMIN::INLANEFREIGHT:f54d6f198a7a47d4:7fecabae13101daaa20f1b09f7f7a4ea:0101000000000000c0653150de09d20126f3f71df13c1fd8000000000200080053004d004200330001001e00570049004e002d00500052004800340039003200520051004100460056000400140053004d00420033002e006c006f00630061006c0003003400570049004e002d00500052004800340039003200520051004100460056002e0053004d00420033002e006c006f00630061006c000500140053004d00420033002e006c006f00630061006c0007000800c0653150de09d201060004000200000008003000300000000000000000000000003000001a67637962f2b7bf297745e6074934196d5f4371b6ba3e796f2997306fd4c1c00a001000000000000000000000000000000000000900280063006900660073002f003100390032002e003100360038002e003100390035002e00310037003000000000000000000000000000:Database99
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: NetNTLMv2
Hash.Target......: SQLADMIN::INLANEFREIGHT:f54d6f198a7a47d4:7fecabae13...000000
Time.Started.....: Fri Aug 28 22:29:26 2020, (6 secs)
Time.Estimated...: Fri Aug 28 22:29:32 2020, (0 secs)
Guess.Base.......: File (/opt/useful/seclists/Passwords/Leaked-Databases/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  1754.7 kH/s (2.32ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 11237376/14344385 (78.34%)
Rejected.........: 0/11237376 (0.00%)
Restore.Point....: 11231232/14344385 (78.30%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: Devanique -> Darrylw
```