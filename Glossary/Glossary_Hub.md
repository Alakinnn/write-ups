> [!NOTE]
> This part only includes definition, not actual resources. For the latter, refer to [[Resources_Hub|Resources_Hub]]

## Shell
Shell(s) are medium/application to help the attack host to execute commands remotely without having to authenticate or re-exploit the vulnerability again by placing the shell(s) inside of the compromised machine, listening to our commands. There are three types of shell:
[[Reverse_Shell]]
[[Bind_Shell]]
[[Web_Shell]]

### Kernel Exploits
Similar to public exploits but instead of on an application, a server. This is executed on machines with outdated, unpatched OS. Can simply be hacked by searching for its respective CVE on Google.

### Enumeration Scripts
EScripts are used for server enumerations, meaning once compromising a server/machine. These scripts can be run to gather information on the machine. However, they generate "noise".

### Vulnerable Software
Software can be databases, key vaults,... they are also penetrable. Look for installed softwares by "dpkg -l" command.

### User Privileges
This is exploiting through the current compromised users. On linux, through sudo - sudo, a prefix used to executing commands on behalf of another users. Refer to [[Resources_Hub]] to see list of commands.


### Scheduled Tasks
Does what its name suggest. However, it is important to check if current user is allowed to write over the scheduled tasks.
1. `/etc/crontab`
2. `/etc/cron.d`
3. `/var/spool/cron/crontabs/root`
   
If one could, simply schedule it to execute a [[Reverse_Shell]] command

### Exposed Credentials
Does what its name suggest. There are configurations files lying around the server or even log files, migration files (some DB administrators create migration files for easy setting up a database)m user history files (bash_history on Linux and PSReadLine on Windows)

This is usually what the "Enumeration Scripts" does.

### SSH Keys
This is dependable on the access of compromised user. There are two scenarios
- If compromised user(CU) only has read access:
	- Retrieving the rsa from .ssh folder
	- chmod 600 that file
	- use that file with flag -i to log in
- If CU has write access:
	- ssh-keygen -f key (-f flag is to specify the output file)
	- there will be 2 files, key and key.pub. the first is used for -i flag when ssh
	- the pub file is placed in the .ssh/authorized_keys

### OPSEC
[[OPSEC]]

