# GoBuster Cheatsheet

## dir buster
```console
~$ gobuster dir -u http://website.com -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories.txt
```
## vhost buster
```console
~$ gobuster vhost -u http://website.com -w /opt/SecList/Discovery/DNS/subdomains-top1million-5000.txt
```
