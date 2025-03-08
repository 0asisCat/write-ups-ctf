# BANDIT

## level 0
pw = bandit0
        cat readme

level 1 pw = ZjLjTmM6FvvyRnrb2rfNWOZOTa6ip5If
        cat < -

level 2 pw = 263JGJPfgU6LtdEvgfWU1XP5yac29mFx
        cat "spaces in this filename"

level 3 pw = MNk8KNH3Usiio41PRUEoDFPqfxLPlSmx
        cat ...Hiding-From-You

level 4 pw = 2WmrDFRmJIq3IPxneAaMGhap0pFhF3NJ
        find . -type f | xargs file | grep text
        cat ./-file07

level 5 pw = 4oQYVPkxZOOEOO5pTW81FB8j8lxXGUQw
        cd inhere
        find . -type f -size 1033c
        cat ./maybehere07/.file2

level 6 pw = HWasnPhtq9AVKe0dmk45nxy20cvUa6EG
        find . -perm -g+r -user bandit7 -group bandit6 -print 2>/dev/null
        cat ./var/lib/dpkg/info/bandit7.password

level 7 pw = morbNTDkSW6jIlUc0ymOdMaLnOlFVAaj
        cat data.txt | grep millionth

level 8 pw = dfwvzFQi4mU0wfNbFOe9RoWskMLg7eEc
        sort data.txt | uniq -u

level 9 pw = 4CKMh1JI91bUIZZPXDqGanal4xvAg0JM
        strings data.txt | grep ===

level 10 pw = FGUW5ilLVJrxX9kMYMmlN4MgbpfMiqey
        base64 -d data.txt

level 11 pw = dtR173fZKb0RRsDFSGsg2RWnpNVj3qRr
        cat data.txt | tr 'A-MN-Za-mn-z' 'N-ZA-Mn-za-m'
        (or simply look online for rot13 decoder)

level 12 pw = 7x16WNeHIi5YkIhWsfFIqoognUTyj9Q4
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
        cat data8

level 13 pw = FO5dwFsc0cbaIiH0h8J2eUks2vdTDwAn
        ls -la
        ssh -i sshkey.private bandit14@bandit.labs.overthewire.org -p 2220

level 14 pw = MU4VWeTyJk8ROof1qqmcBPaLh7lDCPvS
        cat /etc/bandit_pass/bandit14
        (copy the password)
        nc localhost 30000
        (paste the password)

level 15 pw = 8xCjnmgoKbGLhHFAZlGE5Tmu4M2tKJQo
        openssl s_client -connect localhost:30001
        (paste pw)

level 16 pw = kSkvUpMQ7lBYyCM4GBPvCvT1BfWRy0Dx
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

level 17 pw = EReVavePLFHtFlFsjn3hyzMlvSuSAcRD
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

level 18 pw = cGWpMaKXVwDUNgPAVJbWYuGHVn9zl3j8
        ssh bandit18@bandit.labs.overthewire.org -p 2220 ls
        (paste bandit18 pw)
        ssh bandit18@bandit.labs.overthewire.org -p 2220 cat readme
        (paste bandit18 pw)

level 19 pw = cGWpMaKXVwDUNgPAVJbWYuGHVn9zl3j8

