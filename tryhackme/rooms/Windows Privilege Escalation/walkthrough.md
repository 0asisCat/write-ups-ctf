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

## Harversting Passwords from Usual Spots
> This task will present some known places to look for passwords on a Windows system.
> ## 
