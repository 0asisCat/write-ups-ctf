# BANDIT

## Level 0
**pass = bandit0**
```
        cat readme
```

## Level 1
**pass = ZjLjTmM6FvvyRnrb2rfNWOZOTa6ip5If**
```
        cat < -
```

## Level 2
**pass = 263JGJPfgU6LtdEvgfWU1XP5yac29mFx**
```
        cat "spaces in this filename"
```

# Level 3
**pass = MNk8KNH3Usiio41PRUEoDFPqfxLPlSmx**
```
        cat ...Hiding-From-You
```

# Level 4
**pass = 2WmrDFRmJIq3IPxneAaMGhap0pFhF3NJ**
```
        find . -type f | xargs file | grep text
        cat ./-file07                               // OR cat < -file07
```

# Level 5
**pass = 4oQYVPkxZOOEOO5pTW81FB8j8lxXGUQw**
```
        cd inhere
        find . -type f -readable -size 1033c ! -executable
        cat ./maybehere07/.file2
```

# Level 6
**pass = HWasnPhtq9AVKe0dmk45nxy20cvUa6EG**
```
        find . -perm -g+r -user bandit7 -group bandit6 -print 2>/dev/null        // OR find / -type f -size 33c -user bandit7 -group bandit6 2>dev/null
        cat ./var/lib/dpkg/info/bandit7.password
```

# Level 7
**pass = morbNTDkSW6jIlUc0ymOdMaLnOlFVAaj**
```
        cat data.txt | grep millionth
```

# Level 8
**pass = dfwvzFQi4mU0wfNbFOe9RoWskMLg7eEc**
```
        sort data.txt | uniq -u
```

# Level 9
**pass = 4CKMh1JI91bUIZZPXDqGanal4xvAg0JM**
```
        strings data.txt | grep ===
```

# Level 10
**pass = FGUW5ilLVJrxX9kMYMmlN4MgbpfMiqey**
```
        base64 -d data.txt        // OR cat data.txt | base64 -d 
```

# Level 11
**pass = dtR173fZKb0RRsDFSGsg2RWnpNVj3qRr**
```
        cat data.txt | tr 'A-MN-Za-mn-z' 'N-ZA-Mn-za-m'
        (or simply look online for rot13 decoder)
```

# Level 12
**pass = 7x16WNeHIi5YkIhWsfFIqoognUTyj9Q4**
```
        (cheated by getting existing dir in /tmp)
        cd /tmp
        mkdir s3cr3t
        cd s3cr3t
        cp ~/data.txt .
        xxd -r data.txt > binary
        file binary (binary: gzip compressed data)
        mv binary binary.gz
        gunzip binary.gz
        file binary (binary: bzip2 compressed data)
        bunzip2 binary
        file binary.out (binary.out: gzip compressed data)
        mv binary.out binary.gz
        gunzip binary.gz
        file binary (binary: POSIX tar archive)
        tar -xf binary
        file data5.bin (data5.bin: POSIX tar archive) 
        tar -xf data5.bin
        file data6.bin (data6.bin: bzip2 compressed data)
        bunzip2 data6.bin
        file data6.bin.out (data6.bin.out: POSIX tar archive)
        tar -xf data6.bin.out
        file data8.bin(data8.bin: gzip compressed data)
        mv data8.bin data8.gz
        gunzip data8.gz
        cat data8
```

# Level 13
**pass = FO5dwFsc0cbaIiH0h8J2eUks2vdTDwAn**
```
        ls -la
        ssh -i sshkey.private bandit14@bandit.labs.overthewire.org -p 2220
```

# Level 14
**pass = MU4VWeTyJk8ROof1qqmcBPaLh7lDCPvS**
```
        cat /etc/bandit_pass/bandit14
        (copy the password)
        nc localhost 30000
        (paste the password)
```

# Level 15
**pass = 8xCjnmgoKbGLhHFAZlGE5Tmu4M2tKJQo**
```
        openssl s_client -connect localhost:30001
        (paste pw)
```

# Level 16
**pass = kSkvUpMQ7lBYyCM4GBPvCvT1BfWRy0Dx**
```
        ip a s
        (copy ens5)
        nmap -sVC [ens5 ip] -p31000-32000
        (results: 31046 echo, 31518 ssl/echo, 31691 echo, 31790 ssl/uknown, 31960 echo)
        openssl s_client -connect localhost:31790 -quiet
        (paste pw)
        (copy the RSA priv key)
        cd /tmp
        mkdir key
        vim private.key
        (paste the RSA priv key)
        chmod 700 private.key
        ssh -i private.key bandit17@localhost -p 2220
```

# Level 17
**pass = EReVavePLFHtFlFsjn3hyzMlvSuSAcRD**
```
        diff -c passwords.new passwords.old
        (results: 
                from ! ktfgBvpMzWKR5ENj26IbLGSblgUG9CzB 
                to ! x2gLTTjFwMOhQ8oWNbMN362QKxfRqGlO
        )
        (port is closed when performing ssh)
        exit
        ssh bandit18@bandit.labs.overthewire.org -p 2220 ls
        (paste bandit18 pw)
        ssh bandit18@bandit.labs.overthewire.org -p 2220 cat readme
        (paste bandit18 pw)
```

# Level 18
**pass = cGWpMaKXVwDUNgPAVJbWYuGHVn9zl3j8**
```
        ssh bandit18@bandit.labs.overthewire.org -p 2220 ls
        (paste bandit18 pw)
        ssh bandit18@bandit.labs.overthewire.org -p 2220 cat readme
        (paste bandit18 pw)
```

# Level 19
**pass = cGWpMaKXVwDUNgPAVJbWYuGHVn9zl3j8**

