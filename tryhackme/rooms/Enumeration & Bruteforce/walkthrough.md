# TRYHACKME : Enumeration & Bruteforce

Deploy the machine and put `[TARGET-IP] enum.thm` in the `/etc/hosts`

> NOTE: If you ran out of time and restarted the room, you'll need to redo everything from the start to have a smooth ride with this room. When I said from the start, such as doing the first activity from the Verbose errors.

## Enumerating Users via Verbose Errors

Inducing Verbose Errors

Attackers induce verbose errors as a way to force the application to reveal its secrets. Below are some common techniques used to provoke these errors:

- **Invalid Login Attempts:** This is like knocking on every door to see which one will open. By intentionally entering incorrect usernames or passwords, attackers can trigger error messages that help distinguish between valid and invalid usernames. For example, entering a username that doesn’t exist might trigger a different error message than entering one that does, revealing which usernames are active.
- **SQL Injection:** This technique involves slipping malicious SQL commands into entry fields, hoping the system will stumble and reveal information about its database structure. For example, placing a single quote ( ') in a login field might cause the database to throw an error, inadvertently exposing details about its schema.
- **File Inclusion/Path Traversal:** By manipulating file paths, attackers can attempt to access restricted files, coaxing the system into errors that reveal internal paths. For example, using directory traversal sequences like ../../ could lead to errors that disclose restricted file paths.
- **Form Manipulation:** Tweaking form fields or parameters can trick the application into displaying errors that disclose backend logic or sensitive user information. For example, altering hidden form fields to trigger validation errors might reveal insights into the expected data format or structure.
- **Application Fuzzing:** Sending unexpected inputs to various parts of the application to see how it reacts can help identify weak points. For example, tools like Burp Suite Intruder are used to automate the process, bombarding the application with varied payloads to see which ones provoke informative errors.

### Walkthrough

1. Open the Verbose Login page from the http server.
2. Copy the following python script from THM in your machine, and name it `script.py` or whatever you want.
3. Download the list of emails from this [github link](https://github.com/nyxgeek/username-lists/blob/master/usernames-top100/usernames_gmail.com.txt).
4. Then open terminal and run this command: `python3 script.py usernames_gmail.com.txt`.
5. Wait for the valid email to appear.

## Exploiting Vulnerable Password Reset Logic

Password Reset Flow Vulnerabilities

Password reset mechanism is an important part of user convenience in modern web applications. However, their implementation requires careful security considerations because poorly secured password reset processes can be easily exploited.

Email-Based Reset

When a user resets their password, the application sends an email containing a reset link or a token to the user’s registered email address. The user then clicks on this link, which directs them to a page where they can enter a new password and confirm it, or a system will automatically generate a new password for the user. This method relies heavily on the security of the user's email account and the secrecy of the link or token sent.

Security Question-Based Reset

This involves the user answering a series of pre-configured security questions they had set up when creating their account. If the answers are correct, the system allows the user to proceed with resetting their password. While this method adds a layer of security by requiring information only the user should know, it can be compromised if an attacker gains access to personally identifiable information (PII), which can sometimes be easily found or guessed.

SMS-Based Reset

This functions similarly to email-based reset but uses SMS to deliver a reset code or link directly to the user’s mobile phone. Once the user receives the code, they can enter it on the provided webpage to access the password reset functionality. This method assumes that access to the user's phone is secure, but it can be vulnerable to SIM swapping attacks or intercepts.

Each of these methods has its vulnerabilities:

- **Predictable Tokens:** If the reset tokens used in links or SMS messages are predictable or follow a sequential pattern, attackers might guess or brute-force their way to generate valid reset URLs.
- **Token Expiration Issues:** Tokens that remain valid for too long or do not expire immediately after use canderson@gmail.comprovide a window of opportunity for attackers. It’s crucial that tokens expire swiftly to limit this window.
- **Insufficient Validation:** The mechanisms for verifying a user’s identity, like security questions or email-based authentication, might be weak and susceptible to exploitation if the questions are too common or the email account is compromised.
- **Information Disclosure:** Any error message that specifies whether an email address or username is registered can inadvertently help attackers in their enumeration efforts, confirming the existence of accounts.
- **Insecure Transport:** The transmission of reset links or tokens over non-HTTPS connections can expose these critical elements to interception by network eavesdroppers.

### Walkthrough

1. Open the `http:/[TARGET-IP]/labs/predictable_tokens`.
2. Click the "forget password" link.
3. Then enter the valid email from the previous room.
4. Using the `crunch` command, generate a number from 100-200: `crunch 3 3 -o otp.txt -t %%% -s 100 -e 200`.
5. Open burpsuite and capture the request page by entering this as the url: `http://[TARGET-IP]/labs/predictable_tokens/reset_password.php?token=12345` (any random digits)
6. Use the intruder function and load the generated file `opt.txt`. Then start the sniper attack.
7. Filter the length from the highest to lowest.
8. Check the source code of the response with the highest length. There lies the password and email to enter. 
