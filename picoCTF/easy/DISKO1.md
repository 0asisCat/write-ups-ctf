# PICOCTF : DISKO 1

1. Download the disk image from the site.
2. Then navigate to your terminal in the **Downloads/** directory.

```
$ ls -la
-rw-rw-r--  1 oasis oasis 20484478 Aug 16 20:05 disko-1.dd.gz
```

3. Extract the file using `gunzip` command.
```
$ gunzip disko-1.dd.gz
$ ls -la
-rw-rw-r--  1 oasis oasis 52428800 Aug 16 20:05 disko-1.dd
$ file disko-1.dd
disko-1.dd: DOS/MBR boot sector, code offset 0x58+2, OEM-ID "mkfs.fat", Media descriptor 0xf8, sectors/track 32, heads 8, sectors 102400 (volumes > 32 MB), FAT (32 bit), sectors/FAT 788, serial number 0x241a4420, unlabeled
```

4. Now is the time to obtain the flag. We can use the `strings` command to print the readable content. But that it will only drown us into a long amount of strings. We will need to utilize the `grep` command to only print the flag.
```
$ strings disko-1.dd | grep -i picoctf
picoCTF[RETRIEVE-FLAG]
```

