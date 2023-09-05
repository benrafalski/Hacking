# FTP
## Overview
### Port Numbers
* **Command Port** : tcp/21
* **Data Port** :  tcp/20

## FTP Anonymous
### In the console
requires no password
```console
~$ ftp anonymous@{target_IP}
```
### Once in ftp service
list the dir
```console
> dir
```
get a file
```console
> get filename.txt
```
leave
```console
> exit
```