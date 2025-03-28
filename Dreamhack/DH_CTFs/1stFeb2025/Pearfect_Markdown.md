I first test if the system would receive any other files but markdown it did not work
[[Pearfect_Markdown.pdf]]
![[Pasted image 20250201102913.png]]

![[Pasted image 20250201102937.png]]

since it was a markdown, the obvious thing to try is XSS
![[Pasted image 20250201103118.png]]

I then tried to do a reversal with XSS but no matter what directory I use, it gives me the same error
![[Pasted image 20250201103223.png]]
![[Pasted image 20250201103229.png]]
But if I give it a file name that exists on the system. At the same time, the file contains XSS. It works

![[Pasted image 20250201103333.png]]
So I looked up on the internet to see if using a webshell works like this command
```
<?php 
system("ls -la"); 
?>
```

![[Pasted image 20250201103450.png]]

It works, my job left is to find any file on the system with a flag in it
![[Pasted image 20250201103537.png]]

cat the file file and there's the result