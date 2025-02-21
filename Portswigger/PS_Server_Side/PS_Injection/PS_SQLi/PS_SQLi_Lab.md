 **[SQL injection vulnerability in WHERE clause allowing retrieval of hidden data](https://portswigger.net/web-security/sql-injection/lab-retrieve-hidden-data)**
```spoiler-block
Hint: Use the syntax --
```
```spoiler-block
Use an always correct clause
```

[**SQL injection vulnerability allowing login bypass](https://portswigger.net/web-security/sql-injection/lab-login-bypass)**
I tried the username wiener from the lab description with syntax -- '
![[Pasted image 20250214133832.png]]
It works
So it should mean the common admin's username would work
![[Pasted image 20250214133901.png]]

**[SQL injection UNION attack, finding a column containing text](https://portswigger.net/web-security/sql-injection/union-attacks/lab-find-column-containing-text)**
I attempt to find the number of columns by doing the Union select null, and find out that it has 3 columns 
![[Pasted image 20250214140618.png]]
I then tried to add a string in any of the column and it was the 2nd one
![[Pasted image 20250214141353.png]]

Lab solved
![[Pasted image 20250214141407.png]]

**[SQL injection UNION attack, retrieving data from other tables](https://portswigger.net/web-security/sql-injection/union-attacks/lab-retrieve-data-from-other-tables)**

3 nulls gives an error
![[Pasted image 20250214141524.png]]

2 nulls doesnt
![[Pasted image 20250214141535.png]]
Given that the description said the other table was users and have two columns of username and password. So I tried that

![[Pasted image 20250214141616.png]]
Lab solved
![[Pasted image 20250214141628.png]]
**[SQL injection UNION attack, retrieving multiple values in a single column](https://portswigger.net/web-security/sql-injection/union-attacks/lab-retrieve-multiple-values-in-single-column)**

2 nulls to check column quantity

![[Pasted image 20250214141838.png]]

After some trials and errors with cheatsheet, i found out that the database is mysql
![[Pasted image 20250214143038.png]]
From the information from the description, i retrieved the credentials
![[Pasted image 20250214143126.png]]
**[SQL injection attack, querying the database type and version on Oracle](https://portswigger.net/web-security/sql-injection/examining-the-database/lab-querying-database-version-oracle)**
Check for number of columns on Oracle database. This DB requires a table for from (A MUST) so we use dual (a dummy table)
![[Pasted image 20250214143340.png]]

Check for data type
![[Pasted image 20250214143405.png]]
![[Pasted image 20250214143437.png]]
![[Pasted image 20250214143444.png]]

**[SQL injection attack, listing the database contents on Oracle](https://portswigger.net/web-security/sql-injection/examining-the-database/lab-listing-database-contents-oracle)**


Check column type

![[Pasted image 20250214143601.png]]
I forgot to check the data type but it works, lol.
![[Pasted image 20250214144423.png]]
There are 2 users table but this one looks less like a default table 'USERS_EBOEHP'

That shit is right on
![[Pasted image 20250214144549.png]]
|PASSWORD_WUWBYN|
|USERNAME_ZSDBQJ|

Let's use concat since we know it's an Oracle db
![[Pasted image 20250214144747.png]]

Fuck yeahj
![[Pasted image 20250214144756.png]]

  
**[SQL injection attack, querying the database type and version on MySQL and Microsoft](https://portswigger.net/web-security/sql-injection/examining-the-database/lab-querying-database-version-mysql-microsoft)**
I tried a bunch of UNION attacks, a normal attack like Gifts' or 1=1 -- . But that still doesnt work.
But when i do ' or 1=1 -- . There has to be a space otherwise the code breaks. Meaning we are on a Mysql
![[Pasted image 20250214152557.png]]
i have no idea why when I put nulls in to find the number of columns, it fails but this works
![[Pasted image 20250214152803.png]]
**[SQL injection attack, listing the database contents on non-Oracle databases](https://portswigger.net/web-security/sql-injection/examining-the-database/lab-listing-database-contents-non-oracle)**
No space nor table required, we are likely on a postgres or mysql
![[Pasted image 20250214153608.png]]

![[Pasted image 20250214153729.png]]
we are on postgres.
Therefore, with payloadallthethings, we find that the thingy has a user table
![[Pasted image 20250214154758.png]]

users_snzifm
![[Pasted image 20250214154910.png]]
![[Pasted image 20250214154915.png]]
![[Pasted image 20250214155001.png]]



![[Pasted image 20250214180237.png]]

![[Pasted image 20250214181817.png]]
![[Pasted image 20250214181829.png]]

Note: Sometime you have to delete the original value to save space for string limit
![[Pasted image 20250214182727.png]]
![[Pasted image 20250214182742.png]]

Change from username to password:
![[Pasted image 20250214182820.png]]

1v3adk8w095qm8976faj

**[Blind SQL injection with time delays and information retrieval](https://portswigger.net/web-security/sql-injection/blind/lab-time-delays-info-retrieval)**
Payload needs to follow HTML syntax and the right length
![[Pasted image 20250216200055.png]]
Time-based will be determined by RTT
![[Pasted image 20250216200135.png]]
9fdn9087qzef0veux8my