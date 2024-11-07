# brutefh
## ©️ 2023-2024 Claes M Nyberg, cmn@signedness.org

---

<img src="https://github.com/claesmnyberg/brutefh/blob/main/brutefh.gif" width="100%" height="100%"/>

---

## What is this?
This is a tool for brute forcing file handles over NFSv3. 
Accessing a file using a file handle can bypass directory permissions on some operating systems.
Although the system call for resolving a file handle is limitied to root, we can attempt to
brute force it over NFS. The brutefh tool is written as a general tool that can be easily customized
for targeting a specific OS.

OpenBSD for example, uses only 32bit of random which take approximately 75 hours to cover
on a Gigabit network. By running the brute force tool all discovered file handles will be 
printed as soon as they are discovered.

The file handle for a file on OpenBSD has the following structure:

```
File Handle for / (getfh(2), OpenBSD 7.4)
00000000 4123f3ca 0c00 0000 02000000 9485fa86 00000000 00000000
 fh_fsid[0]: 00000000 (0)            /* FS ID of mount point (available from statfs(2), 0 for root fs) */
 fh_fsid[1]: 4123f3ca (-890035391)   /* FS ID of mount point (available from statfs(2)) */
    fid_len: 0c00 (12)               /* Length of data in bytes (starting at random:, always 12?)) */ 
   reserved: 0000 (0)                /* Unused */
      inode: 02000000 (2)            /* inode (always 2 on fs root directory, get it from stat(2)) */
     random: 9485fa86 (-2030402156)  /* Randomized value from fsirand(8), newfs() takes care of that now */
       zero: 00000000 (0)            /* Always zero? */
       zero: 00000000 (0)            /* Always zero? */



```
