## Description
![[Pasted image 20250228181938.png]]

## Category
#web 
## Solution
The original website is a photo, hosted on a S3 bucket. 
![[Pasted image 20250227195657.png]]

As I read on google, one of the exploits for S3 is misconfiguration. As in you can see all content of a bucket.

Checking out to the bucket:
![[Pasted image 20250227195734.png]]

A bit of digging led to this 
![[Pasted image 20250227195755.png]]

It is a base64 encrypted string, which is easy
![[Pasted image 20250227195810.png]]
