## Flags

- --**dbms**=MySQL: This flag specifies the database management system to target. By setting it to MySQL, you instruct sqlmap to use techniques specifically for exploiting MySQL databases.
    
- --**technique**=T: This option tells sqlmap to use only the “time-based blind” SQL injection technique for testing. The “T” represents time-based blind SQL injection, which relies on the time it takes to receive a response to infer information about the database.
    
- --**time**-**sec**=10: Sets the number of seconds to wait before considering a response to be delayed. In this case, sqlmap will wait for 10 seconds to determine if the server is responding slowly, which helps in time-based SQL injection techniques.
    
- --**level**=5: This option sets the level of tests to perform. Levels range from 1 to 5, with level 5 being the most thorough. It increases the number of tests that sqlmap conducts, which can lead to a better chance of discovering vulnerabilities.
    
- --**risk**=3: Sets the risk level for tests. Risk levels range from 0 to 3, with 3 being the highest. Higher risk levels enable more aggressive tests, which may be more likely to exploit vulnerabilities.
    
- --**fresh**-**queries**: This flag tells sqlmap to ignore cached data and to re-execute all queries against the database. This ensures that any changes to the database since the last query execution are accounted for.
    
- --**no**-**cast**: This option disables automatic type casting of data. When enabled, sqlmap tries to cast data types (e.g., converting strings to integers), which might not be necessary or could lead to incorrect results. Disabling it can sometimes provide more accurate outcomes.
    
- --**r** Case2.txt: This option specifies that SQLmap should read the HTTP request from the file Case2.txt. The file typically contains the raw HTTP request, including headers, cookies, etc., needed for the injection test.
    
- --**threads** 10: Runs SQLmap using 10 threads to speed up the scanning process.
    
- --**dump** -**T** flag2: Instructs SQLmap to dump (extract) all data from the table named flag2.
    
- --**batch**: Runs SQLmap in non-interactive mode, automatically using default options when prompts appear, which is useful for scripting or automation.
    
- -**p** **cookie**: This flag specifies the parameter to be tested for SQL injection. In this case, it’s instructing sqlmap to focus on the cookie parameter found in the request. If the cookie contains something like id=123, SQLmap will target that part for testing.
    
- --**csrf**-token=**t0ken**: This flag is used to specify a CSRF (Cross-Site Request Forgery) token. Many modern web applications use CSRF tokens to prevent unauthorized actions on behalf of a user.
    
    - In this case, t0ken is the placeholder for the actual CSRF token that the web application is using. Sqlmap will substitute this token in each request to bypass CSRF protection
        
- --**randomize**=uid: The --randomize flag is used to randomize the value of a specific parameter (in this case, uid) in each HTTP request. This is often done to avoid detection by web application firewalls (WAFs) or intrusion detection systems (IDS).
    
    - Randomizing a parameter like uid simulates different users, making the attack harder to detect by automated defenses that might trigger if the same request is made repeatedly.
        
- --**prefix**=: This flag allows you to specify a prefix to prepend to the extracted data.
    
- --**union**-**cols**=5: Specifies the number of columns to be used in a UNION query during the SQL injection exploitation. By setting this flag to 5, you are instructing sqlmap to assume that the vulnerable query returns 5 columns. This is important for constructing valid UNION queries, as both the original and injected queries must have the same number of columns to work correctly.
    

Basic DB Data Enumeration

Usually, after a successful detection of an SQLi vulnerability, we can begin the enumeration of basic details from the database, such as the hostname of the vulnerable target (--hostname), current user's name (--current-user), current database name (--current-db), or password hashes (--passwords). SQLMap will skip SQLi detection if it has been identified earlier and directly start the DBMS enumeration process.

Enumeration usually starts with the retrieval of the basic information:

- Database version banner (switch --banner)
    
- Current user name (switch --current-user)
    
- Current database name (switch --current-db)
    
- Checking if the current user has DBA (administrator) rights (switch --is-dba)
    

Table Enumeration

In most common scenarios, after finding the current database name (i.e. testdb), the retrieval of table names would be by using the --tables option and specifying the DB name with -D testdb, is as follows:

After spotting the table name of interest, retrieval of its content can be done by using the --dump option and specifying the table name with -T users, as follows:

Table/Row Enumeration

When dealing with large tables with many columns and/or rows, we can specify the columns (e.g., only name and surname columns) with the -C option, as follows:

Conditional Enumeration

If there is a requirement to retrieve certain rows based on a known WHERE condition (e.g. name LIKE 'f%'), we can use the option --where, as follows:

Full DB Enumeration

Instead of retrieving content per single-table basis, we can retrieve all tables inside the database of interest by skipping the usage of option -T altogether (e.g. --dump -D testdb). By simply using the switch --dump without specifying a table with -T, all of the current database content will be retrieved. As for the --dump-all switch, all the content from all the databases will be retrieved.

In such cases, a user is also advised to include the switch --exclude-sysdbs (e.g. --dump-all --exclude-sysdbs), which will instruct SQLMap to skip the retrieval of content from system databases, as it is usually of little interest for pentesters.

DB Schema Enumeration

If we wanted to retrieve the structure of all of the tables so that we can have a complete overview of the database architecture, we could use the switch --schema:

Searching for Data

When dealing with complex database structures with numerous tables and columns, we can search for databases, tables, and columns of interest, by using the --search option. This option enables us to search for identifier names by using the LIKE operator. For example, if we are looking for all of the table names containing the keyword user, we can run SQLMap as follows:

In the above example, we can immediately spot a couple of interesting data retrieval targets based on these search results. We could also have tried to search for all column names based on a specific keyword (e.g. pass):

Password Enumeration and Cracking

Once we identify a table containing passwords (e.g. master.users), we can retrieve that table with the -T option, as previously shown:

DB Users Password Enumeration and Cracking

Apart from user credentials found in DB tables, we can also attempt to dump the content of system tables containing database-specific credentials (e.g., connection credentials). To ease the whole process, SQLMap has a special switch --passwords designed especially for such a task: