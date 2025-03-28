## Description
Welcome to the challenge! In this challenge, you will explore a web application and find an endpoint that exposes a file containing a hidden flag. The application is a simple blog website where you can read articles about various topics, including an article about API Documentation. Your goal is to explore the application and find the endpoint that generates files holding the server’s memory, where a secret flag is hidden.

## Category
#web 

## Score
50

## Hints
Hint 1:
Explore backend development with us

Hint 2: The head was dumped.
## Solution
### Enumeration
![[Pasted image 20250309195120.png]]

The base website is just a bunch of posts talking about API. The word "head" in the name `head-dump` may make some think of a `HEAD` request. But this challenge remind us that exploring all accessible (sometimes supposedly-inaccessible) endpoints when attack a web.


A little digging around the site (no tools involved). I found its documentation page:
![[Pasted image 20250309195317.png]]
The heapdump endpoint seems suspicious

### Exploitation
Getting the site gives me a download file
![[Pasted image 20250309195404.png]]

I open with Notepad and search for flag:
![[Pasted image 20250309195434.png]]
