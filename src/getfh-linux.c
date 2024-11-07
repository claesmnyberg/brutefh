/*
 * Translate name to file handle on Linux.
 * Claes M Nyberg, December 2023, <cmn@signedness.org>
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int
main(int argc, char **argv)
{
	struct file_handle *fh;	
	int mnt_id;
	int n;

	if (argc != 2) {
		printf("Usage: %s <path>\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	if ( (fh = calloc(1, sizeof(struct file_handle) + MAX_HANDLE_SZ)) == NULL) {
		perror("calloc");
		exit(EXIT_FAILURE);
	}
	fh->handle_bytes = MAX_HANDLE_SZ;


	if (name_to_handle_at(AT_FDCWD, argv[1], fh, &mnt_id, AT_EMPTY_PATH | AT_SYMLINK_FOLLOW) < 0) {
		perror("name_to_handle_at");
		exit(EXIT_FAILURE);
	}

	printf("%s\n", argv[1]);
	printf("Mount ID: %d (0x%x)\n", mnt_id, mnt_id);
	printf("fh->handle_bytes: %d\n", fh->handle_bytes);
	printf("fh->handle_type: %d\n", fh->handle_type);
	printf("fh->f_handle: ");
	for (n=0; n<fh->handle_bytes; n++) {
		printf("%02x", fh->f_handle[n]);
	}
	printf("\n");
	free(fh);

}

