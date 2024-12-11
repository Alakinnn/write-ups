### Introduction
This is the first ever exercise on Cyber Advent. Day 1 focuses on "Forensics" with the use of exiftool, malware analysis (sort of) and an exemplary failure regarding [[OPSEC]]


![[Screenshot 2024-12-11 at 14.20.48.png]]
After extracting the zip, there as suspiciously mispelt file while turns out to be 

![[Screenshot 2024-12-11 at 14.27.30.png]]
After running Exiftool, I can be that the file when run will trigger Window's powershell with flags -ep Bypass -nop that disables Powershell's restrictions.

It will then attempt to download a file called IS.ps1 and rename it to s.ps1 then run it with iex

The s.ps1 is used to scan the system for credentials like crypto wallets and send it back to the remote hosts.

### Tips
> There are many ways to back track this even further by investigating the website on which we download the file from, analyse it source code or search for open directories and public malware databases. The latter is important since not all hackers actually write their own scripts and download from some place else.


![[Screenshot 2024-12-11 at 14.32.16.png]]
This is what the scripts look like, information like its creator can be used as search values. This case, on Github.