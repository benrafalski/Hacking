# GoBuster Cheatsheet

## dir buster
```bash
gobuster dir -u http://website.com -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories.txt
```
## vhost buster
```bash
gobuster vhost -u http://website.com -w /opt/SecList/Discovery/DNS/subdomains-top1million-5000.txt
```

## subdomain buster
```bash
gobuster dns -d website.com -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -t 20
```
