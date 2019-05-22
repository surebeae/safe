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

#include <sodium.h>

#include "arg.h"
#include "queue.h"
#include "readpassphrase.h"

#define MDSIZE crypto_generichash_BYTES
#define SAFE ".secrets"
#define META ".meta"

struct secret {
	char name[64];
	char hex[MDSIZE*2 + 1];
	SLIST_ENTRY(secret) entry;
};

struct safe {
	uint8_t salt[crypto_pwhash_SALTBYTES];
	uint32_t nentry;
	SLIST_HEAD(secrets, secret) secrets;
};

char *argv0;

uint8_t key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
uint8_t *passphrase;
uint32_t pplen;

void
usage(void)
{
	fprintf(stderr, "usage: %s [-h] [-s safe] [[-a] entry]\n", argv0);
	exit(1);
}

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

static int
readpass(const char *prompt, uint8_t **target, uint32_t *len)
{
	char pass[BUFSIZ], *p;

	p = readpassphrase(prompt, pass, sizeof(pass), RPP_ECHO_OFF);
	if (!p)
		err(1, "readpassphrase:");

	if (p[0] == '\0')
		return -1;

	*target = realloc(*target, strlen(p)); /* not null-terminated */
	if (!*target)
		err(1, "realloc:");

	memcpy(*target, p, strlen(p));
	*len = strlen(p);
	return 0;
}

void
hash(uint8_t *buf, size_t size, uint8_t *md, size_t mdsize)
{
	crypto_generichash(md, mdsize, buf, size, NULL, 0);
}

void
deriv(char *pw, struct safe *s)
{
	if (crypto_pwhash(key, sizeof(key), pw, strlen(pw),
			s->salt, crypto_pwhash_OPSLIMIT_INTERACTIVE,
			crypto_pwhash_MEMLIMIT_INTERACTIVE,
			crypto_pwhash_ALG_DEFAULT))
		err(1, "crypto_pwhash");
}

void
list_secrets(struct safe *s)
{
	struct secret *tmp;
	SLIST_FOREACH(tmp, &s->secrets, entry)
		printf("%s\t%s\n", tmp->hex, tmp->name);
}

int
store_secret(struct safe *s, int fd, char *name)
{
	int sfd;
	ssize_t n;
	uint8_t md[MDSIZE];
	char buf[64], fn[MDSIZE*2 + 1];
	struct secret *secret;

	secret = malloc(sizeof(*secret));
	strcpy(secret->name, name);

	hash((uint8_t *)name, strlen(name), md, sizeof(md));
	bin2str(md, secret->hex, MDSIZE);

	sfd = open(secret->hex, O_WRONLY | O_CREAT, 0600);
	if (sfd < 0)
		err(1, "open %s", fn);

	while((n = xread(fd, buf, sizeof(buf))) > 0) {
		xwrite(sfd, buf, n);
	}

	close(sfd);

	SLIST_INSERT_HEAD(&s->secrets, secret, entry);
	s->nentry++;

	return 0;
}

int
show_secret(struct safe *s, int fd, char *name)
{
	int sfd;
	ssize_t n;
	uint8_t md[MDSIZE];
	char buf[64], fn[MDSIZE*2 + 1];

	hash((uint8_t *)name, strlen(name), md, sizeof(md));
	bin2str(md, fn, MDSIZE);

	sfd = open(fn, O_RDONLY);
	if (sfd < 0)
		err(1, "open %s", fn);

	while((n = xread(sfd, buf, sizeof(buf))) > 0) {
		xwrite(fd, buf, n);
	}

	close(sfd);
	return 0;
}

void
init(struct safe *s)
{
	int fd;
	uint32_t i;
	struct stat sb;
	struct secret *secret;

	if (sodium_init() < 0)
		err(1, "sodium: failed to initialize library");

	SLIST_INIT(&s->secrets);

	if (!stat(META, &sb)) {
		fd = open(META, O_RDONLY);

		xread(fd, s->salt, sizeof(s->salt));
		xread(fd, &s->nentry, sizeof(s->nentry));
		for (i = 0; i < s->nentry; i++) {
			secret = malloc(sizeof(*secret));
			xread(fd, secret->name, sizeof(secret->name));
			xread(fd, secret->hex, sizeof(secret->hex));
			SLIST_INSERT_HEAD(&s->secrets, secret, entry);
		}

		close(fd);
	} else {
		s->nentry = 0;
		randombytes_buf(s->salt, sizeof(s->salt));
	}
}

void
deinit(struct safe *s)
{
	int fd;
	struct secret *tmp;

	fd = open(META, O_WRONLY | O_CREAT, 0600);

	xwrite(fd, s->salt, sizeof(s->salt));
	xwrite(fd, &s->nentry, sizeof(s->nentry));
	SLIST_FOREACH(tmp, &s->secrets, entry) {
		xwrite(fd, tmp->name, sizeof(tmp->name));
		xwrite(fd, tmp->hex, sizeof(tmp->hex));
	}

	fsync(fd);
	close(fd);
}

int
main(int argc, char *argv[])
{
	int aflag = 0, lflag = 0;
	char *secret = NULL, *safe = SAFE;
	struct safe s;

	ARGBEGIN {
	case 'a':
		aflag = 1;
		break;
	case 'l':
		lflag = 1;
		break;
	case 's':
		safe = EARGF(usage());
		break;
	default:
		usage();
	} ARGEND

	if (argc != 1 && !lflag)
		usage();

	if (safe) {
		mkdir(safe, 0700);
		if (chdir(safe) < 0)
			err(1, "chdir: %s", safe);
	}

	init(&s);

	readpass("Passphrase:", &passphrase, &pplen);
	deriv((char *)passphrase, &s);

	secret = argv[0];

	if (lflag) {
		list_secrets(&s);
		return 0;
	} else if (aflag) {
		store_secret(&s, STDIN_FILENO, secret);
		deinit(&s);
	} else {
		show_secret(&s, STDOUT_FILENO, secret);
	}

	return 0;
}

