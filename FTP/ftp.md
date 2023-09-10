# FTP
## Overview
### Port Numbers
* **Command Port** : tcp/21
* **Data Port** :  tcp/20

## FTP Anonymous
### In the console
requires no password
```bash
~$ ftp anonymous@{target_IP}
```
### Once in ftp service
list the dir
```bash
> dir
```
get a file
```bash
> get filename.txt
```
leave
```bash
> exit
```