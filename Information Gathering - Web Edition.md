## Whois
Each WHOIS record typically contains the following information:

- `Domain Name`: The domain name itself (e.g., example.com)
- `Registrar`: The company where the domain was registered (e.g., GoDaddy, Namecheap)
- `Registrant Contact`: The person or organization that registered the domain.
- `Administrative Contact`: The person responsible for managing the domain.
- `Technical Contact`: The person handling technical issues related to the domain.
- `Creation and Expiration Dates`: When the domain was registered and when it's set to expire.
- `Name Servers`: Servers that translate the domain name into an IP address.

```
whois domain
```

## DNS
|Tool|Key Features|Use Cases|
|---|---|---|
|`dig`|Versatile DNS lookup tool that supports various query types (A, MX, NS, TXT, etc.) and detailed output.|Manual DNS queries, zone transfers (if allowed), troubleshooting DNS issues, and in-depth analysis of DNS records.|
|`nslookup`|Simpler DNS lookup tool, primarily for A, AAAA, and MX records.|Basic DNS queries, quick checks of domain resolution and mail server records.|
|`host`|Streamlined DNS lookup tool with concise output.|Quick checks of A, AAAA, and MX records.|
|`dnsenum`|Automated DNS enumeration tool, dictionary attacks, brute-forcing, zone transfers (if allowed).|Discovering subdomains and gathering DNS information efficiently.|
|`fierce`|DNS reconnaissance and subdomain enumeration tool with recursive search and wildcard detection.|User-friendly interface for DNS reconnaissance, identifying subdomains and potential targets.|
|`dnsrecon`|Combines multiple DNS reconnaissance techniques and supports various output formats.|Comprehensive DNS enumeration, identifying subdomains, and gathering DNS records for further analysis.|
|`theHarvester`|OSINT tool that gathers information from various sources, including DNS records (email addresses).|Collecting email addresses, employee information, and other data associated with a domain from multiple sources.|
|Online DNS Lookup Services|User-friendly interfaces for performing DNS lookups.|Quick and easy DNS lookups, convenient when command-line tools are not available, checking for domain availability or basic information|
### Common dig Commands

|Command|Description|
|---|---|
|`dig domain.com`|Performs a default A record lookup for the domain.|
|`dig domain.com A`|Retrieves the IPv4 address (A record) associated with the domain.|
|`dig domain.com AAAA`|Retrieves the IPv6 address (AAAA record) associated with the domain.|
|`dig domain.com MX`|Finds the mail servers (MX records) responsible for the domain.|
|`dig domain.com NS`|Identifies the authoritative name servers for the domain.|
|`dig domain.com TXT`|Retrieves any TXT records associated with the domain.|
|`dig domain.com CNAME`|Retrieves the canonical name (CNAME) record for the domain.|
|`dig domain.com SOA`|Retrieves the start of authority (SOA) record for the domain.|
|`dig @1.1.1.1 domain.com`|Specifies a specific name server to query; in this case 1.1.1.1|
|`dig +trace domain.com`|Shows the full path of DNS resolution.|
|`dig -x 192.168.1.1`|Performs a reverse lookup on the IP address 192.168.1.1 to find the associated host name. You may need to specify a name server.|
|`dig +short domain.com`|Provides a short, concise answer to the query.|
|`dig +noall +answer domain.com`|Displays only the answer section of the query output.|
|`dig domain.com ANY`|Retrieves all available DNS records for the domain (Note: Many DNS servers ignore `ANY` queries to reduce load and prevent abuse, as per [RFC 8482](https://datatracker.ietf.org/doc/html/rfc8482)).|

## Subdomain
|Tool|Description|
|---|---|
|[dnsenum](https://github.com/fwaeytens/dnsenum)|Comprehensive DNS enumeration tool that supports dictionary and brute-force attacks for discovering subdomains.|
|[fierce](https://github.com/mschwager/fierce)|User-friendly tool for recursive subdomain discovery, featuring wildcard detection and an easy-to-use interface.|
|[dnsrecon](https://github.com/darkoperator/dnsrecon)|Versatile tool that combines multiple DNS reconnaissance techniques and offers customisable output formats.|
|[amass](https://github.com/owasp-amass/amass)|Actively maintained tool focused on subdomain discovery, known for its integration with other tools and extensive data sources.|
|[assetfinder](https://github.com/tomnomnom/assetfinder)|Simple yet effective tool for finding subdomains using various techniques, ideal for quick and lightweight scans.|
|[puredns](https://github.com/d3mondev/puredns)|Powerful and flexible DNS brute-forcing tool, capable of resolving and filtering results effectively.|

### DNSEnum
```bash
dnsenum --enum inlanefreight.com -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -r
```

## Zone Transfers
```shell-session
[!bash!]$ dig axfr @nsztm1.digi.ninja zonetransfer.me
```

## Virtual Hosts
### Virtual Host Discovery Tools
|Tool|Description|Features|
|---|---|---|
|[gobuster](https://github.com/OJ/gobuster)|A multi-purpose tool often used for directory/file brute-forcing, but also effective for virtual host discovery.|Fast, supports multiple HTTP methods, can use custom wordlists.|
|[Feroxbuster](https://github.com/epi052/feroxbuster)|Similar to Gobuster, but with a Rust-based implementation, known for its speed and flexibility.|Supports recursion, wildcard discovery, and various filters.|
|[ffuf](https://github.com/ffuf/ffuf)|Another fast web fuzzer that can be used for virtual host discovery by fuzzing the `Host` header.|Customizable wordlist input and filtering options.|
```shell-session
[!bash!]$ gobuster vhost -u http://inlanefreight.htb:81 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --append-domain
```
