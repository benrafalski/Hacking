# SQL
## Databases
- store and access data
- Platforms: PostgreSQL, MySQL/MariaSQL, MS SQL Server, Microsoft Access, SQLite
- SQL: language used to communicate with database

## Operators
```sql
-- AND/OR
SELECT * FROM Customers
WHERE Country = 'Spain' AND (CustomerName LIKE 'G%' OR CustomerName LIKE 'R%');
```
### LIKE
```sql
-- The percent sign % represents zero, one, or multiple characters
SELECT * FROM Customers WHERE CustomerName LIKE 'a%';
-- The underscore sign _ represents one, single character
SELECT * FROM Customers WHERE city LIKE 'L_nd__';
-- The [] wildcard returns a result if any of the characters inside gets a match.
SELECT * FROM Customers WHERE CustomerName LIKE '[bsp]%';
-- The - wildcard allows you to specify a range of characters inside the [] wildcard.
SELECT * FROM Customers WHERE CustomerName LIKE '[a-f]%';
```
### NOT, BETWEEN, IN
```sql
-- NOT LIKE
SELECT * FROM Customers WHERE CustomerName NOT LIKE 'A%';
-- NOT BETWEEN
SELECT * FROM Customers WHERE CustomerID NOT BETWEEN 10 AND 60;
-- NOT IN
SELECT * FROM Customers WHERE City NOT IN ('Paris', 'London');
```
### NULL
```sql
-- IS NULL
SELECT column_names FROM table_name WHERE column_name IS NULL;
-- IS NOT NULL
SELECT column_names FROM table_name WHERE column_name IS NOT NULL;
```

## Clauses
### TOP
```sql
-- SQL Server
SELECT TOP 3 * FROM Customers;
```
### LIMIT
```sql
-- MySQL
SELECT * FROM Customers LIMIT 3;
```
### FETCH FIRST
```sql
-- Oracle
SELECT * FROM Customers FETCH FIRST 3 ROWS ONLY;
```
### PERCENT
```sql
-- SQL Server
SELECT TOP 50 PERCENT * FROM Customers;
-- Oracle
SELECT * FROM Customers FETCH FIRST 50 PERCENT ROWS ONLY;
```
## Functions
### MIN() and MAX()
```sql
-- MIN()
SELECT MIN(column_name) as alias FROM table_name;
-- MAX()
SELECT MAX(column_name) as alias FROM table_name;
```
### COUNT()
```sql
-- get number of records
SELECT COUNT(*) AS [number of records] from table_name;
-- get number of non-duplicate records
SELECT COUNT(DISTINCT column_name) from table_name;
```
### SUM()
```sql
-- SUM()
SELECT SUM(column_name) as alias FROM table_name;
```
### AVG()
```sql
-- AVG()
SELECT AVG(column_name) FROM table_name;
```

## Join
```sql

```

