# TRYHACKME : mKingdom

Another CMS beginner room to practice.

## Enumeration

### NMAP
```
PORT   STATE SERVICE VERSION
85/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
|_http-title: 0H N0! PWN3D 4G4IN
|_http-server-header: Apache/2.4.7 (Ubuntu)
Device type: general purpose
Running: Linux 4.X
OS CPE: cpe:/o:linux:linux_kernel:4.4
OS details: Linux 4.4 
Network Distance: 5 hops

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   131.40 ms 10.4.0.1
2   ... 4
5   330.85 ms 10.201.36.52
```

This one leads us to port 85. A troll page. Let's fuzz!

### Gobuster
/app                  (Status: 301) [Size: 312] [--> http://10.201.36.52:85/app/]      
```
```
Now we find an interesting blog page, about mushrooms... Mario's fav I see. Let's check sum more.

This site is built in **Concrete5** CMS.

Let's do sum further enumeration:
```
$ whatweb http://10.201.36.52:85/app/castle/index.php/blog
http://10.201.36.52:85/app/castle/index.php/blog [200 OK] Apache[2.4.7],
Bootstrap, Concrete5[8.5.2], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.7 (Ubuntu)],
IP[10.201.36.52], JQuery, MetaGenerator[concrete5 - 8.5.2], PHP[5.5.9-1ubuntu4.29], Script[text/javascript],
Title[Blog :: toad], X-Frame-Options[SAMEORIGIN], X-Powered-By[PHP/5.5.9-1ubuntu4.29], X-UA-Compatible[IE=edge]
```

This is using an **8.5.2** version of Concrete5... Let's see if there's an existing exploit.

### Exploit
Can't find on **Searchsploit** so let's get our search browsers.

And [Voila!](https://hackerone.com/reports/768322). An RCE exploit.

But we need first to access the admin access...

#### Admin

Inspecting the site, you'll find a log in button at the bottom of the page. (Hard for me to see)

We can try some bruteforce.

Before trying some enormous bruteforce, let's enter basic credentials: `admin:password`.

Another voila.

We can now upload the reverse shell!

> Below the **Dashboard**, proceed to the following order: **System & Settings** > **Allowed File Types** > Add **php** in the end > then save.

After the allowing php, get a php reverse shell. You can get one in Kali: **/usr/share/webshells/php/php-reverse-shell.php**.

> Still in the **Dashboard**, head to **Files**, then upload the php file.
> Start a listener on local machine, then click the url leading you to the php file.

## Shell
Stabilize first the shell for smooth compromise.

> Enter in the target machine:
> ```
> python3 -c ‘import pty;pty.spawn(“/bin/bash”)’
> ```
> Enter **ctrl + z** to put the shell in the background for a sec.
> Then enter this in the host machine, to go back to the shell:
> ```
> stty raw -echo; fg
> ```
> Then enter:
> ```
> export TERM=xterm
> ```

## Privilege Escalation

### www-data to Toad

There are no found vulnerabilities but leaks with further enumeration.
There's also no user flag to be retrieved in this user.
There's a readable sql data nearby though.
Concatenate **/var/www/html/app/castle/application/config/database.php** and retrieve the said credentials.

### Toad to Mario

There's also no user flag to be retrieved in here.
It was also tricky to find system vulnerabilities, but we can from simple carelessness.
Check the environment variables:
```
toad@mkingdom:~$ env
...
PWD_token=[RETRIEVE-BASE64-CODE]
...
```
Decode the base64 code into plain text.

### Mario to Root

We can now finally retrieve the user flag.
Escalating to root is going to be complicated. But hang on.

The vulnerability leads us to cronjob. 


