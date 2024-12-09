A reverse shell means that the shell is on the attack host and not the compromised host.

This works by when and only when we have comprised the machine.

First, start a listener like netcat on XXXX port.
Second, go into the machine and execute commands based on its OS. These commands are not equally good with some being better. Commands can be found on https://swisskyrepo.github.io/InternalAllTheThings/cheatsheets/shell-reverse-cheatsheet/. 
Third, execute the command on the remote host back to our IP and listening port.
Fourth, from our listener, execute commands.

Pros: Easy, quick.
Cons: Once lose connection, have to regain access somehow.





