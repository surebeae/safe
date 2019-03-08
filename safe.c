#include <sys/stat.h>
#include <sys/types.h>

#include <err.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/sha.h>

#include "arg.h"

#define MDSIZE 32
#define SAFE ".safe.d"

char *argv0;

void
str2bin(char *s, uint8_t *d, size_t size)
{
	size_t i;

	for (i = 0; i < size; i++, s += 2)
		sscanf(s, "%2hhx", &d[i]);
}

void
bin2str(uint8_t *d, char *s, size_t size)
{
	size_t i;

	for (i = 0; i < size; i++, s += 2)
		sprintf(s, "%02x", d[i]);
}

ssize_t
xread(int fd, void *buf, size_t nbytes)
{
	uint8_t *bp = buf;
	ssize_t total = 0;

	while (nbytes > 0) {
		ssize_t n;

		n = read(fd, &bp[total], nbytes);
		if (n < 0)
			err(1, "read");
		else if (n == 0)
			return total;
		total += n;
		nbytes -= n;
	}
	return total;
}

ssize_t
xwrite(int fd, const void *buf, size_t nbytes)
{
	const uint8_t *bp = buf;
	ssize_t total = 0;

	while (nbytes > 0) {
		ssize_t n;

		n = write(fd, &bp[total], nbytes);
		if (n < 0)
			err(1, "write");
		else if (n == 0)
			return total;
		total += n;
		nbytes -= n;
	}
	return total;
}

void
usage(void)
{
	fprintf(stderr, "usage: %s [-h] [-s safe] [-p pass] [[-a] entry]\n", argv0);
	exit(1);
}

void
hash(uint8_t *buf, size_t size, uint8_t *md)
{
	SHA256_CTX ctx;

	SHA256_Init(&ctx);
	SHA256_Update(&ctx, buf, size);
	SHA256_Final(md, &ctx);
}

void
hash_key(char *pass)
{
	size_t i;
	uint8_t md[MDSIZE];
	char key[MDSIZE * 2];

	hash((uint8_t *)pass, strlen(pass), md);
	bin2str(md, key, MDSIZE);

	for (i = 0; i < sizeof(key); i++)
		key[i] &= 1;

	setkey(key);
}

void
xencrypt(char *s, size_t size, int edflag)
{
	size_t i, j;
	char buf[64];

	if (size > 8)
		xencrypt(s+8, size - 8, edflag);

	for (i = 0; i < 8; i ++)
		for (j = 0; j < 8; j++)
			buf[i * 8 + j] = s[i] >> j & 1;

	encrypt(buf, edflag);
	for (i = 0; i < 8; i++)
		for (j = 0; j < 8; j++)
			s[i] |= buf[i * 8 + j] << j;

}

int
store_secret(int fd, char *name)
{
	int sfd;
	ssize_t n;
	uint8_t md[MDSIZE];
	char buf[64], fn[MDSIZE*2 + 1];

	hash((uint8_t *)name, strlen(name), md);
	bin2str(md, fn, MDSIZE);

	sfd = open(fn, O_WRONLY | O_CREAT, 0600);
	if (sfd < 0)
		err(1, "open %s", fn);

	while((n = xread(fd, buf, sizeof(buf))) > 0) {
		/* xencrypt(buf, sizeof(buf), 0); */
		xwrite(sfd, buf, n);
	}

	close(sfd);
	return 0;
}

int
show_secret(int fd, char *name)
{
	int sfd;
	ssize_t n;
	uint8_t md[MDSIZE];
	char buf[64], fn[MDSIZE*2 + 1];

	hash((uint8_t *)name, strlen(name), md);
	bin2str(md, fn, MDSIZE);

	sfd = open(fn, O_RDONLY);
	if (sfd < 0)
		err(1, "open %s", fn);

	while((n = xread(sfd, buf, sizeof(buf))) > 0) {
		/* xencrypt(buf, sizeof(buf), 1); */
		xwrite(fd, buf, n);
	}

	close(sfd);
	return 0;
}

int
main(int argc, char *argv[])
{
	int aflag = 0;
	char *secret = NULL, *pass = NULL, *safe = SAFE;

	ARGBEGIN {
	case 'a':
		aflag = 1;
		break;
	case 'p':
		pass = EARGF(usage());
		break;
	case 's':
		safe = EARGF(usage());
		break;
	default:
		usage();
	} ARGEND

	if (argc != 1)
		usage();


	if (safe) {
		mkdir(safe, 0700);
		if (chdir(safe) < 0)
			err(1, "chdir: %s", safe);
	}

	if (pass)
		hash_key(pass);

	secret = argv[0];

	if (aflag) {
		store_secret(STDIN_FILENO, secret);
	} else {
		show_secret(STDOUT_FILENO, secret);
	}

	return 0;
}