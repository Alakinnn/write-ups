Bind shell is the opposite with reverse shell.

This type of shell also needs a compromised machine. Once compromised, run a command to "bind" a port onto that machine respective os terminal, meaning that the port and the ip, for example 0.0.0.0 is ready to be connected to from anywhere.

Using netcat to connect is an option

### Upgrading TTY
- Only works when the netcat shell has already been connected

	The reasons to upgrade TTY is that it is only possible to delete and enter new command but now moving the cursor.

```
python -c 'import pty; pty.spawn("/bin/bash")'
```
	The command above is used to upgrade TTY, must be sent in the netcat shell aka the remote-controlled shell

After that is done, ctrl-Z to bring our terminal to the front.
```
stty raw -echo
fg
```
	line by line. fg is to bring the netcat shell back to the foreground.