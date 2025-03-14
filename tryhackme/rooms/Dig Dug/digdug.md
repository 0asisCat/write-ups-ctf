# TRYHACKME : DIG DUG

Start the target machine and set-up your vpn for local machine.

## NMAP
```
$ nmap -sVC -T5 10.10.88.248
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-14 02:21 CST
Warning: 10.10.88.248 giving up on port because retransmission cap hit (2).
Nmap scan report for 10.10.88.248
Host is up (0.40s latency).
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 78:a1:03:f7:b5:d1:99:2c:cf:8e:45:24:0b:84:73:e8 (RSA)
|   256 54:d0:1d:a9:7a:c7:a9:80:b9:4f:61:c9:ed:83:f4:db (ECDSA)
|_  256 71:b4:06:af:8b:f0:d0:eb:05:24:7b:14:87:2e:22:ee (ED25519)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.62 seconds
```
Nothing special I think.

## DIG
```
$ dig 10.10.88.248 givemetheflag.com A                          

; <<>> DiG 9.20.4-4-Debian <<>> 10.10.88.248 givemetheflag.com A
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 45630
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1232
;; QUESTION SECTION:
;10.10.88.248.                  IN      A

;; Query time: 0 msec
;; SERVER: 192.168.254.254#53(192.168.254.254) (UDP)
;; WHEN: Fri Mar 14 02:44:13 CST 2025
;; MSG SIZE  rcvd: 41

;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 5292
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1232
;; QUESTION SECTION:
;givemetheflag.com.             IN      A

;; Query time: 4 msec
;; SERVER: 192.168.254.254#53(192.168.254.254) (UDP)
;; WHEN: Fri Mar 14 02:44:13 CST 2025
;; MSG SIZE  rcvd: 46
```


