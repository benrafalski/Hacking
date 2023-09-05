# SMB
## Overview
* **Port Number**: tcp/455

## smbclient

### Command line
List shares
* *-N* &#8594; no password
* *-L* &nbsp;&#8594; list shares using this IP address
```console
~$ smbclient -N -L \\\\{IP ADDRESS}\\

Sharename       Type      Comment
---------       ----      -------
ADMIN$          Disk      Remote Admin
backups         Disk      
C$              Disk      Default share
IPC$            IPC       Remote IPC
```

This command will connect us to a directory called backups
```console
~$ smbclient -N \\\\{IP ADDRESS}\\backups
```

### Useful commands after connecting to a share
Download a file to our local machine
```console
> get {filename}
```

These are the available commands we can use once connected to backups:

```console
allinfo        altname        archive        backup         
blocksize      cancel         case_sensitive cd             chmod          
chown          close          del            deltree        dir            
du             echo           exit           get            getfacl        
geteas         hardlink       help           history        iosize         
lcd            link           lock           lowercase      ls             
l              mask           md             mget           mkdir          
more           mput           newer          notify         open           
posix          posix_encrypt  posix_open     posix_mkdir    posix_rmdir    
posix_unlink   posix_whoami   print          prompt         put            
pwd            q              queue          quit           readlink       
rd             recurse        reget          rename         reput          
rm             rmdir          showacls       setea          setmode        
scopy          stat           symlink        tar            tarmode        
timeout        translate      unlock         volume         vuid           
wdel           logon          listconnect    showconnect    tcon           
tdis           tid            utimes         logoff         ..             
!
```


