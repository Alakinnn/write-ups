## Description
A developer has added profile picture upload functionality to a website. However, the implementation is flawed, and it presents an opportunity for you. Your mission, should you choose to accept it, is to navigate to the provided web page and locate the file upload area. Your ultimate goal is to find the hidden flag located in the `/root` directory.

## Category
#web 

## Score
100
## Hints
Hint 1:
File upload was not sanitized

Hint 2: Whenever you get a shell on a remote machine, check `sudo -l`
## Solution
### Enumeration
The main page is an image upload
![[Pasted image 20250309200633.png]]

For every problem with uploading file, we are gonna do two things:
1. Banner grabbing
2. Proxy using either BurpSuite or Owasp-Zap

From Wappalyzer (also an extension), we see that the page runs on PHP
![[Pasted image 20250309200724.png]]

So we will use webshell written in PHP. For this challenge I use payload from: https://gist.github.com/joswr1ght/22f40787de19d80d110b37fb79ac3985

### Exploitation
After you get a file, you need to change its extension to a valid png.
![[Pasted image 20250309201846.png]]

However, sometimes changing only the extension is not enough because of the signature nature of PNG file.

Therefore, you have to go to `hexedit` and change the first 3 hex so that it reads PNG
![[Pasted image 20250309201957.png]]

After you upload you need to change both file name and data from
![[Pasted image 20250309202112.png]]
To
![[Pasted image 20250309202150.png]]
File successfully uploaded, we only need to visit the url
![[Pasted image 20250309202212.png]]
We got denied here
![[Pasted image 20250309202302.png]]
So we need to `sudo` everything related to root
![[Pasted image 20250309202320.png]]

flag:
![[Pasted image 20250309202338.png]]
