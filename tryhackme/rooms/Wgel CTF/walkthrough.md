# TRYHACKME : Wgel CTF

# ENUMERATION
## NMAP 
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 94:96:1b:66:80:1b:76:48:68:2d:14:b5:9a:01:aa:aa (RSA)
|   256 18:f7:10:cc:5f:40:f6:cf:92:f8:69:16:e2:48:f4:38 (ECDSA)
|_  256 b9:0b:97:2e:45:9b:f3:2a:4b:11:c7:83:10:33:e0:ce (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## GOBUSTER
```
/.htpasswd            (Status: 403) [Size: 276]
/.hta                 (Status: 403) [Size: 276]
/.htaccess            (Status: 403) [Size: 276]
/index.html           (Status: 200) [Size: 11374]
/server-status        (Status: 403) [Size: 276]
/sitemap              (Status: 301) [Size: 312] [--> http://10.10.19.88/sitemap/]    
```

## GOBUSTER /sitemap
```
/.ssh                 (Status: 301) [Size: 317] [--> http://10.10.19.88/sitemap/.ssh/]              
/.htaccess            (Status: 403) [Size: 276]
/.hta                 (Status: 403) [Size: 276]
/.htpasswd            (Status: 403) [Size: 276]
/css                  (Status: 301) [Size: 316] [--> http://10.10.19.88/sitemap/css/]               
/fonts                (Status: 301) [Size: 318] [--> http://10.10.19.88/sitemap/fonts/]             
/images               (Status: 301) [Size: 319] [--> http://10.10.19.88/sitemap/images/]            
/index.html           (Status: 200) [Size: 21080]
/js                   (Status: 301) [Size: 315] [--> http://10.10.19.88/sitemap/js/] 
```

