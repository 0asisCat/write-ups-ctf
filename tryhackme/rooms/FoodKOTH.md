# TRYHACKME : KoTH Food CTF
***NOTE: IN PROGRESS LMAO***

## NMAP
nmap -T4 -p- -v 10.10.46.26

ports:
PORT      STATE SERVICE
22/tcp    open  ssh
3306/tcp  open  mysql
9999/tcp  open  abyss
15065/tcp open  unknown
16109/tcp open  unknown
46969/tcp open  unknown

## Enumeration
exploit: CVE-2020-14567 (vulnerability in MySQL server product)

## http://10.10.46.26:15065/ ##

HTTP/1.1 200 OK
Accept-Ranges: bytes
Content-Length: 359
Content-Type: text/html; charset=utf-8
Last-Modified: Sun, 05 Apr 2020 23:29:57 GMT
Date: Tue, 04 Mar 2025 02:54:10 GMT

<!DOCTYPE html>
<html>

<head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <title>Host monitoring</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
</head>
<body>
    <h1>Site down for maintenance</h1>
    <p>Blame Dan, he keeps messing with the prod servers.</p>
</body>

## GOBUSTER
gobuster dir -u http://$ip:15065/ -w /usr/share/wordlists/dirb/big.txt

/monitor

## http://10.10.46.26:15065/monitor/ #####
(Possible command injection)

(input some ip, then check dev tools > network > click POST > request)
note: $ip:15065/api/cmd

(on terminal)
sudo url $ip:15065/api/cmd -X POST -d "ls -lah"


## SSH
initials: Dan

python3 /usr/share/john/ssh2john.py


## MYSQL
mysql -u root -h $ip -p
