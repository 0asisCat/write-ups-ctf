# TRYHACKME : OWASP Juice Shop
> **NOTE: Straightforward write-up. If not for you, go find somewhere else.**

## Enumeration

Emails:
- admin@juice-sh.op
- bender@juice-sh.op
- uvogin@juice-sh.op
- jim@juice-sh.op
- mc.safesearch@juice-sh.op

Website:
- Parameter used for searching: "http://10.10.77.172/#/search?q=a' or q
- Jim reference in his review: Star Trek
        - important: he's into star trek

## Exploit:
### Sql injection 
```
        - use burp, intercept login packet, change body to login as Admin:
                - from: {"email":"admin","password":"password"}
                - to: {"email":"' or 1=1--","password":"a"}
                - this will login as user id 0
                - use 1=1 to be used when email or username is not known or invalid
                - user '-- to bypass the login system
        - login to Bender's account:
                - {"email":"bender@juice-sh.op'--","password":"a"}
```

### Broken Authentication
```
        - bruteforce the administrator account's password
                - intercept login traffic, send to intruder
                        - add two § as the  password value from body
                                - it's quotation in burp
                        - for payload, use best1050.txt from Seclists
                                - from /usr/share/wordlists/SecLists/Passwords/Common-Credentials/best1050.txt
                        - start the attack and filter to show only 200 response
                - password: admin123
        - reset Jim's password by exploiting the password mechanism:
                - he's into star trek. look up wikipedia about Jim star Trek and find his brother's middle name: samuel
                - answer: Samuel
```

### Sensitive Data Exposure 
```
        - access the about us page of the website from admin's or any user
                - click the "Check out our boring terms of use..."
                        - it will like into http://10.10.97.60/ftp/legal.md
                        - it will lead you into the /ftp/ directory open to public
        - log into MC SafeSearch's account:
                - email:  mc.safesearch@juice-sh.op
                - pass: Mr. N00dles (from his rap lyrics)
        - download a backup file called package.json.bak
                - we will be met with an error stating that md and pdf are only downloadable
                - use character bypass called "Poison Null Byte" = %00
                        - its actually a NULL terminator. concat it with a string and it will tell the server to terminate at that point nulling the rest of the string
                - we need to encode it into a url encoded format
                        - poison null byte: %2500 then add .md to the end to bypass 403 error
                - input: 10.10.x.x/ftp/package.json.bak%2500.md
```

### Broken Access Control
```
- two types of BAC exploit or bug:
        1. Horizontal Privilege Escalation - access others data within the same level permission
        2. Vertical Privilege Escalation - acces others data with higher level permission
        - access the administration page: 
                - go to the Debbuger within the developer's tool
                - look within "main-es2015.js", click {} for readable input
                - find "admin", then look for "path: administration"
                - login to admin's account before inputting /administration path
        - view other user's shopping basket:
                - capture the request when getting into "your basket"
                - change the 1 from "GET /rest/basket/1 HTTP/1.1" into 2
        - damage the website reputation and remove 5 star review
                - go to the /#/administration
                - click the trash bin beside the 5 star review
```

### Cross-Site Scripting XSS
```
- XSS is a vulnerability that allows attackers to run javascript in web application
- three major types: 
1 DOM XSS = uses HTML environment to execute malicious js. uses <script></script> tag
2 Persistent XSS = the js that is run when the server loads the page containing it. occurs when the server does not sanitise the user data when uploaded to a page. found on blog posts
3 Reflected XSS = js that is run on the client-side end of the web app. occurs when the server doesnt sanitise search data
        - perform DOM XSS:
                - input <iframe src="javascript:alert('xss')"> within the search bar
                - also called as XFS (Cross-Frame Scripting), common forms of detectingXSS within web applications
        - perform Persistent XSS:
                - login as the admin
                - we will logout to log the 'new' ip for the Last Login IP page
                - it will appear first at 0.0.0.0 or 10.x.x.x
                - intercept the logout request in burp
                - add in the Header's tab= True-Client-IP: <iframe src="javascript:alert(`xss`)"> 
                - the forward the request to the server
                - when we login as admin again, the xss alert will replace the ip
        - perform Reflected XSS:
                - navigate the order history page, click the truck icon
                - you will see the link bar contains a id parameter
                - we will use XFS to replace the id value
                - it will then pop a xss frame
```

## FOR MORE OWASP JUICE SHOP CHALLENGES
- enter to url `/score-board`
