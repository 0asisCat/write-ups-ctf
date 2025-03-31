# TRYHACKME : Summit

> Following the Pyramid of Pain's ascending priority of indicators, your objective is to increase the simulated adversaries' cost of operations and chase them away for good. Each level of the pyramid allows you to detect and prevent various indicators of attack.

## NMAP
```
$ nmap -sVC 10.10.176.82    
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-31 08:49 CST
Nmap scan report for 10.10.176.82
Host is up (0.40s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 c7:62:f6:e8:81:3b:0b:fc:28:f4:a7:3e:e4:b5:4f:20 (RSA)
|   256 42:e6:31:a6:98:7c:f5:09:f5:f5:db:d2:58:8c:52:30 (ECDSA)
|_  256 75:56:b5:08:3a:08:d0:1a:61:82:ad:e9:8e:bb:6e:4a (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: TryHackMe | Summit
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 26.27 seconds
```

