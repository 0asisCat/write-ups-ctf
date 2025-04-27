# TRYHACKME : Wonderland

Deploy the machine and set up your vpn.

## NMAP 

```
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 61 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 8e:ee:fb:96:ce:ad:70:dd:05:a9:3b:0d:b0:71:b8:63 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDe20sKMgKSMTnyRTmZhXPxn+xLggGUemXZLJDkaGAkZSMgwM3taNTc8OaEku7BvbOkqoIya4ZI8vLuNdMnESFfB22kMWfkoB0zKCSWzaiOjvdMBw559UkLCZ3bgwDY2RudNYq5YEwtqQMFgeRCC1/rO4h4Hl0YjLJufYOoIbK0EPaClcDPYjp+E1xpbn3kqKMhyWDvfZ2ltU1Et2MkhmtJ6TH2HA+eFdyMEQ5SqX6aASSXM7OoUHwJJmptyr2aNeUXiytv7uwWHkIqk3vVrZBXsyjW4ebxC3v0/Oqd73UWd5epuNbYbBNls06YZDVI8wyZ0eYGKwjtogg5+h82rnWN
|   256 7a:92:79:44:16:4f:20:43:50:a9:a8:47:e2:c2:be:84 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHH2gIouNdIhId0iND9UFQByJZcff2CXQ5Esgx1L96L50cYaArAW3A3YP3VDg4tePrpavcPJC2IDonroSEeGj6M=
|   256 00:0b:80:44:e6:3d:4b:69:47:92:2c:55:14:7e:2a:c9 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAsWAdr9g04J7Q8aeiWYg03WjPqGVS6aNf/LF+/hMyKh
80/tcp open  http    syn-ack ttl 61 Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-title: Follow the white rabbit.
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## PORT 80

Contains a picture of rabbit and text:

```
Follow the White Rabbit.

"Curiouser and curiouser!" cried Alice (she was so much surprised, that for the moment she quite forgot how to speak good English)
```

## GOBUSTER

```
/img                  (Status: 301) [Size: 0] [--> img/]
/index.html           (Status: 301) [Size: 0] [--> ./]
/r                    (Status: 301) [Size: 0] [--> r/]                                              
```


## PORT 80/r

```
Keep Going.

"Would you tell me, please, which way I ought to go from here?"
```

## GOBUSTER

```
/a                    (Status: 301) [Size: 0] [--> a/]
/index.html           (Status: 301) [Size: 0] [--> ./]
```

## PORT 80/r/a

```
Keep Going.

"That depends a good deal on where you want to get to," said the Cat.
```

> **I'm starting to see a pattern here."**

## RABBIT DIRECTORIES

```
PORT 80/r/a/b
"" 
Keep Going.

"I don’t much care where—" said Alice.
""
```
```
PORT 80/r/a/b/b
"" 
Keep Going.

"Then it doesn’t matter which way you go," said the Cat.
""
```
```
PORT 80/r/a/b/b/i
"" 
Keep Going.

"—so long as I get somewhere,"" Alice added as an explanation.
""
```
```
PORT 80/r/a/b/b/i/t
""
Open the door and enter wonderland

"Oh, you’re sure to do that," said the Cat, "if you only walk long enough."

Alice felt that this could not be denied, so she tried another question. "What sort of people live about here?"

"In that direction,"" the Cat said, waving its right paw round, "lives a Hatter: and in that direction," waving the other paw, "lives a March Hare. Visit either you like: they’re both mad."
""
```

I did another gobuster but it seems to be the dead end.

Let's download the two alice_door images instead.

```
wget -O alice.png http://10.10.92.172/img/alice_door.png
wget -O alice.jpg http://10.10.92.172/img/alice_door.jpg
```
The huge file size of these picture seems really suspicious. Im guessing that each represents the Hatter and the March Hare.

Let's download the white rabbit too.

```
wget -O alice.jpg http://10.10.92.172/img/alice_door.jpg
```

## STEGANOGRAPHY

I tried using it first with the white rabbit.
```
$ steghide extract -sf whiteR.jpg
Enter passphrase:                   // JUST HIT ENTER
wrote extracted data to "hint.txt".
$ cat hint.txt        
follow the r a b b i t
```

The clue is something we already did with the directories.

Now with the remaining two alice images:
```
$ steghide extract -sf alice.png 
Enter passphrase: 
steghide: the file format of the file "alice.png" is not supported.
$ steghide extract -sf alice.jpg
Enter passphrase: 
steghide: could not extract any data with that passphrase!
```

It seems that the case of `alice.png` is not steganography.

