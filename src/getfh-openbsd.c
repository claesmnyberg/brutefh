/*
 * Get filehandle for path on OpenBSD.
 * Tested on OpenBSD 7.2
 * Claes M Nyberg <cmn@signedness.org>
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/mount.h>

 /* From sys/mount.h: */
#if 0
typedef struct { int32_t val[2]; } fsid_t;      /* file system id type */
/*
 * File identifier.
 * These are unique per filesystem on a single machine.
 */
#define MAXFIDSZ        16
struct fid {
        u_short         fid_len;                /* length of data in bytes */
        u_short         fid_reserved;           /* force longword alignment */
        char            fid_data[MAXFIDSZ];     /* data (variable length) */
};
/*
 * Generic file handle
 */
struct fhandle {
        fsid_t  fh_fsid;        /* File system id of mount point */
        struct  fid fh_fid;     /* File sys specific id */
};
typedef struct fhandle  fhandle_t;
#endif

#define HEXDUMP(_data, _len)        \
{                                   \
    int c = 0;                      \
    while (c < _len) {              \
        printf("%02x", *((char *)_data + c));   \
        c++;                        \
    }                               \
    printf("\n");                   \
}
int
printfh(char *path)
{
    fhandle_t fh; 
    struct fhdata {
        uint32_t inode;
        uint32_t random; 
        uint32_t d3;
        uint32_t d4;
    } *dp;

    memset(&fh, 0x00, sizeof(fh));
    if (getfh(path, &fh) != 0) {
        perror("getfh");
        return -1;
    }
    printf("Raw FH dump: ");
    HEXDUMP(&fh, sizeof(fh));

    /* Convert to network byte order */
    fh.fh_fsid.val[0] = htonl(fh.fh_fsid.val[0]);
    fh.fh_fsid.val[1] = htonl(fh.fh_fsid.val[1]);
    fh.fh_fid.fid_len = htons(fh.fh_fid.fid_len);
    fh.fh_fid.fid_reserved = htons(fh.fh_fid.fid_reserved);

    dp = (struct fhdata *)&fh.fh_fid.fid_data;
    dp->inode = htonl(dp->inode);
    dp->random = htonl(dp->random);
    dp->d3 = htonl(dp->d3);
    dp->d4 = htonl(dp->d4);

    printf("Converted to network byte order\n");
    printf("%08x", fh.fh_fsid.val[0]);
    printf("%08x", fh.fh_fsid.val[1]);
    printf("%04x", fh.fh_fid.fid_len);
    printf("%04x", fh.fh_fid.fid_reserved);
    printf("%08x", dp->inode);
    printf("%08x", dp->random);
    printf("%08x", dp->d3);
    printf("%08x\n", dp->d4);

    printf("\nStructured\n");
    printf("%08x ", fh.fh_fsid.val[0]);
    printf("%08x ", fh.fh_fsid.val[1]);
    printf("%04x ", fh.fh_fid.fid_len);
    printf("%04x ", fh.fh_fid.fid_reserved);
    printf("%08x ", dp->inode);
    printf("%08x ", dp->random);
    printf("%08x ", dp->d3);
    printf("%08x\n", dp->d4);


    printf(" fh_fsid[0]: %08x (%d)    \t\t/* FS ID of mount point (available from statfs(2)) */\n", fh.fh_fsid.val[0], ntohl(fh.fh_fsid.val[0]));
    printf(" fh_fsid[1]: %08x (%d)    \t\t/* FS ID of mount point (available from statfs(2)) */\n", fh.fh_fsid.val[1], ntohl(fh.fh_fsid.val[1]));
    printf("    fid_len: %04x (%d)    \t\t/* Length of data in bytes (starting at random, always 12?)) */ \n", fh.fh_fid.fid_len, ntohs(fh.fh_fid.fid_len));
    printf("   reserved: %04x (%d)\n", fh.fh_fid.fid_reserved, ntohs(fh.fh_fid.fid_reserved));
    printf("      inode: %08x (%d)    \t\t/* Just the inode (always 2 on fs root directory, get it from stat(2)) */\n", dp->inode, ntohl(dp->inode));
    printf("     random: %08x (%d)    \t\t/* Randomized value */\n", dp->random, ntohl(dp->random));
    printf("       zero: %08x (%d)    \t\t/* Always zero? */\n", dp->d3, ntohl(dp->d3));
    printf("       zero: %08x (%d)    \t\t/* Always zero? */\n", dp->d4, ntohl(dp->d4));
    return 0;
}

int
main(int argc, char **argv)
{
    if (argc != 2) {
        printf("Usage: %s <path>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    printfh(argv[1]);
}

