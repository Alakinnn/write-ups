## Description

Oops! I accidentally spilled paint all over my canvas. Now, the colors have blended too well :(  
Can you restore my lost artwork?

## Category
#steganography

## Solution
The given file is an svg with only sky blue color
![[Pasted image 20250304170138.png]]

From an SVG editor, we can see that there's a blocking square and the background-color with the line color,  `#a2b5e0` and `#a2b5e4` are almost the same.

![[Pasted image 20250304170320.png]]

If we remove the square and change the background color. A text reveals
![[Pasted image 20250304170349.png]]

The flag would be `VishwaCTF{STROKE__N_FILL}`