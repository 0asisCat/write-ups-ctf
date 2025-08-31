# TRYHACKME : Hijack
Misconfigs conquered, identities claimed.

## NMAP
```
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.3
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 94:ee:e5:23:de:79:6a:8d:63:f0:48:b8:62:d9:d7:ab (RSA)
|   256 42:e9:55:1b:d3:f2:04:b6:43:b2:56:a3:23:46:72:c7 (ECDSA)
|_  256 27:46:f6:54:44:98:43:2a:f0:59:ba:e3:b6:73:d3:90 (ED25519)
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Home
|_http-server-header: Apache/2.4.18 (Ubuntu)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
111/tcp  open  rpcbind 2-4 (RPC #100000)
|_rpcinfo: ERROR: Script execution failed (use -d to debug)
2049/tcp open  nfs     2-4 (RPC #100003)
Device type: general purpose
Running: Linux 4.X
OS CPE: cpe:/o:linux:linux_kernel:4.4
OS details: Linux 4.4
Network Distance: 5 hops
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   128.32 ms 10.4.0.1
2   ... 4
5   327.72 ms 10.201.20.95
```

## PORT 21 FTP

## PORT 80 HTTP

### GOBUSTER
```
$ gobuster dir -u "http://10.201.9.217/" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x .php                        
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.201.9.217/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 277]
/index.php            (Status: 200) [Size: 487]
/login.php            (Status: 200) [Size: 822]
/signup.php           (Status: 200) [Size: 1002]
/logout.php           (Status: 302) [Size: 0] [--> index.php]
/config.php           (Status: 200) [Size: 0]                     // !!!!! INTERESTING !!!!!!
/administration.php   (Status: 200) [Size: 51]
/navbar.php           (Status: 200) [Size: 304]

```

### WEB ENUM
The main page is under construction and there seems to be nothing interesting.

Even the `config.php` only displays a blank page, although we can access the session cookies but it's not really useful. The `administration.php` is also inaccessible.

Let's try signing up. My created credential is `oas:password`

I tried going back to the `config.php` after signing up, and there seems to be interesting with the cookies.

<img width="1305" height="939" alt="Image" src="https://github.com/user-attachments/assets/a7c403bf-8144-4087-b2a8-621d4f7fe1d9" />

The cookie seems interesting. I tried to crack it on [cyberchef](https://gchq.github.io/CyberChef/), and sure enough we got a BASE64 encoded string. 

<img width="1044" height="515" alt="Image" src="https://github.com/user-attachments/assets/5075ab4b-6ed5-44a4-941e-6d8cc72cc12b" />

It is in a `username:password` format I reckon. I tried it on [crackstation](https://crackstation.net/) and my guess was right.

<img width="1021" height="73" alt="Image" src="https://github.com/user-attachments/assets/f2806a66-c0d2-4e6f-ace5-20d3e658910a" />

### BRUTEFORCE


## PORT 111 RPCBIND

```
$ rpcinfo -p 10.201.20.95   
   program vers proto   port  service
    100000    4   tcp    111  portmapper
    100000    3   tcp    111  portmapper
    100000    2   tcp    111  portmapper
    100000    4   udp    111  portmapper
    100000    3   udp    111  portmapper
    100000    2   udp    111  portmapper
    100005    1   udp  40564  mountd
    100005    1   tcp  39409  mountd
    100005    2   udp  58657  mountd
    100005    2   tcp  40059  mountd
    100005    3   udp  34771  mountd
    100005    3   tcp  42954  mountd
    100003    2   tcp   2049  nfs
    100003    3   tcp   2049  nfs
    100003    4   tcp   2049  nfs
    100227    2   tcp   2049  nfs_acl
    100227    3   tcp   2049  nfs_acl
    100003    2   udp   2049  nfs
    100003    3   udp   2049  nfs
    100003    4   udp   2049  nfs
    100227    2   udp   2049  nfs_acl
    100227    3   udp   2049  nfs_acl
    100021    1   udp  52516  nlockmgr
    100021    3   udp  52516  nlockmgr
    100021    4   udp  52516  nlockmgr
    100021    1   tcp  44585  nlockmgr
    100021    3   tcp  44585  nlockmgr
    100021    4   tcp  44585  nlockmgr

$ nc -zvu 10.201.20.95 111          
10.201.20.95: inverse host lookup failed: Unknown host
(UNKNOWN) [10.201.20.95] 111 (sunrpc) open

```
