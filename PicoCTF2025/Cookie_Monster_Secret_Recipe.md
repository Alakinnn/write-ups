## Description
Cookie Monster has hidden his top-secret cookie recipe somewhere on his website. As an aspiring cookie detective, your mission is to uncover this delectable secret. Can you outsmart Cookie Monster and find the hidden recipe?

## Category
#web 

## Score
50

## Hints
Hint 1:
Sometimes, the most important information is hidden in plain sight. Have you checked all parts of the webpage?

Hint 2: Cookies aren't just for eating - they're also used in web technologies!

Hint 3: Web browsers often have tools that can help you inspect various aspects of a webpage, including things you can't see directly.

## Solution
### Enumeration
![[Pasted image 20250309194505.png]]

A simple login form. Since the challenge mention cookie, what every sane man does is to check the cookie session.

I use the cookie-editor extension, available to download on all large browsers.

![[Pasted image 20250309194640.png]]

We see a long string in the cookie. There are characters that seem odd which are the `%3D%3D`. This is the URL encoded text of the `=` symbol. Which makes that two equal's.

From this information, we can easily know the cookie is just a base64 encoded string.

### Exploitation
We can use PicoCTF's browser shell to decode or https://www.base64decode.org
![[Pasted image 20250309195001.png]]

