#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sodium.h>

#include "arg.h"
#include "readpassphrase.h"

#define MASTER  "master"
#define SAFE    ".secrets"

struct safe {
	uint8_t key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
	uint8_t salt[crypto_pwhash_SALTBYTES];
};

enum {
	SAFE_INIT  = 1 << 1,
	SAFE_FINAL = 1 << 2,
};

uint8_t *passphrase;
size_t pplen;
char *argv0;

void
usage(void)
{
	fprintf(stderr, "usage: %s [-h] [-s safe] [[-a] entry]\n", argv0);
	exit(1);
}

char *
dirname(char *path)
{
	static char tmp[PATH_MAX];
	char *p = NULL;
	size_t len;
	snprintf(tmp, sizeof(tmp), "%s", path);
	len = strlen(tmp);
	for(p = tmp + len; p > tmp; p--)
		if(*p == '/')
			break;

	*p = 0;
	return tmp;
}

int
mkdir_p(char *path, mode_t mode)
{
	char tmp[PATH_MAX] = "";
	char *p = NULL;
	size_t len;

	snprintf(tmp, sizeof(tmp), "%s", path);
	len = strlen(tmp);
	if(len && tmp[len - 1] == '/')
		tmp[len - 1] = 0;
	for(p = tmp + 1; *p; p++)
		if(*p == '/') {
			*p = 0;
			mkdir(tmp, mode);
			*p = '/';
		}
	return mkdir(tmp, mode);
}

ssize_t
xread(int fd, void *buf, size_t nbytes, int *eof)
{
	uint8_t *bp = buf;
	ssize_t total = 0;

	if (eof) *eof = 0;
	while (nbytes > 0) {
		ssize_t n;

		n = read(fd, &bp[total], nbytes);
		if (n < 0) {
			err(1, "read");
		} else if (n == 0) {
			if (eof) *eof = 1;
			return total;
		}
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

int
readpass(const char *prompt, uint8_t **target, size_t *len)
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
deriv(char *pw, struct safe *s)
{
	if (crypto_pwhash(s->key, sizeof(s->key), pw, strlen(pw),
			s->salt, crypto_pwhash_OPSLIMIT_INTERACTIVE,
			crypto_pwhash_MEMLIMIT_INTERACTIVE,
			crypto_pwhash_ALG_DEFAULT))
		err(1, "crypto_pwhash:");
}

int
pushkey(struct safe *s, char *path)
{
	int sfd;
	struct sockaddr_un addr;

	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, path);

	if ((sfd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
		return -1;

	if (connect(sfd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
		return -1;

	if (xwrite(sfd, s->salt, sizeof(s->salt)) < 0)
		return -1;

	if (write(sfd, s->key, sizeof(s->key)) < 0)
		return -1;

	close(sfd);

	return 0;
}

int
readkey(struct safe *s, char *path)
{
	int sfd;
	ssize_t n;
	struct sockaddr_un addr;

	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, path);

	if ((sfd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
		return -1;

	if (connect(sfd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
		goto err;

	if ((n = xread(sfd, s->salt, sizeof(s->salt), NULL)) <= 0)
		goto err;

	if (xread(sfd, s->key, sizeof(s->key), NULL) < 0)
		goto err;

	close(sfd);
	return 0;

err:
	close(sfd);
	return -1;
}

int
trydecrypt(struct safe *s, int fd)
{
	int eof = 0;
	ssize_t n;
	uint8_t tag;
	uint8_t m[BUFSIZ];
	uint8_t c[BUFSIZ + crypto_secretstream_xchacha20poly1305_ABYTES];
	uint8_t h[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
	crypto_secretstream_xchacha20poly1305_state st;
	unsigned long long mlen;

	xread(fd, h, sizeof(h), NULL);
	if (crypto_secretstream_xchacha20poly1305_init_pull(&st, h, s->key))
		return -1;

	while ((n = xread(fd, c, sizeof(c), &eof)) > 0) {
		if (crypto_secretstream_xchacha20poly1305_pull(&st, m, &mlen, &tag, c, n, NULL, 0))
			return -1;

		if (eof && tag != crypto_secretstream_xchacha20poly1305_TAG_FINAL)
			return -1;
	}
	return 0;
}

int
writepass(struct safe *s, uint8_t *m, size_t mlen, int fd)
{
	uint8_t *c, h[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
	crypto_secretstream_xchacha20poly1305_state st;
	unsigned long long clen;

	c = malloc(mlen + crypto_secretstream_xchacha20poly1305_ABYTES);
	if (!c)
		err(1, "malloc");

	if (crypto_secretstream_xchacha20poly1305_init_push(&st, h, s->key))
		return -1;

	if (crypto_secretstream_xchacha20poly1305_push(&st, c, &clen, m, mlen, NULL, 0, crypto_secretstream_xchacha20poly1305_TAG_FINAL))
		return -1;

	xwrite(fd, h, sizeof(h));
	xwrite(fd, c, clen);

	free(c);

	return 0;
}

int
writesecret(struct safe *s, int in, int out)
{
	int eof;
	ssize_t n;
	uint8_t tag;
	uint8_t m[BUFSIZ];
	uint8_t c[BUFSIZ + crypto_secretstream_xchacha20poly1305_ABYTES];
	uint8_t h[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
	crypto_secretstream_xchacha20poly1305_state st;
	unsigned long long clen;

	if (crypto_secretstream_xchacha20poly1305_init_push(&st, h, s->key))
		return -1;

	xwrite(out, h, sizeof(h));

	while ((n = xread(in, m, sizeof(m), &eof)) > 0) {
		tag = eof ? crypto_secretstream_xchacha20poly1305_TAG_FINAL : 0;
		if (crypto_secretstream_xchacha20poly1305_push(&st, c, &clen, m, n, NULL, 0, tag))
			return -1;

		xwrite(out, c, clen);
	}
	return 0;
}

int
readsecret(struct safe *s, int in, int out)
{
	int eof = 0;
	ssize_t n;
	uint8_t tag;
	uint8_t m[BUFSIZ];
	uint8_t c[BUFSIZ + crypto_secretstream_xchacha20poly1305_ABYTES];
	uint8_t h[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
	crypto_secretstream_xchacha20poly1305_state st;
	unsigned long long mlen;

	xread(in, h, sizeof(h), NULL);
	if (crypto_secretstream_xchacha20poly1305_init_pull(&st, h, s->key))
		return -1;

	while ((n = xread(in, c, sizeof(c), &eof)) > 0) {
		if (crypto_secretstream_xchacha20poly1305_pull(&st, m, &mlen, &tag, c, n, NULL, 0))
			return -1;

		if (eof && tag != crypto_secretstream_xchacha20poly1305_TAG_FINAL)
			return -1;

		xwrite(out, m, mlen);
	}
	return 0;
}

int
main(int argc, char *argv[])
{
	int fd, haskey = 0, aflag = 0, pflag = 0;
	char *secret = NULL, *sockp = NULL, *safe = SAFE;
	struct safe s;

	safe  = getenv("SAFE_DIR");
	sockp = getenv("SAFE_SOCK");

	ARGBEGIN {
	case 'a':
		aflag = 1;
		break;
	case 'p':
		pflag = 1;
		break;
	case 's':
		safe = EARGF(usage());
		break;
	default:
		usage();
	} ARGEND

	if (argc != 1 && !pflag)
		usage();

	if (sodium_init() < 0)
		return -1;

	if (!safe)
		safe = SAFE;

	mkdir(safe, 0700);
	if (chdir(safe) < 0)
		err(1, "chdir: %s", safe);

	/* open master password as read only to retrieve salt */
	fd = open(MASTER, O_RDONLY);
	if (fd < 0 && errno != ENOENT)
		err(1, "%s", MASTER);

	if (sockp && !pflag) {
		if (!readkey(&s, sockp))
			haskey = 1;
	}

	if (!haskey) {
		readpass("password:", &passphrase, &pplen);

		/* write master password entry if not present */
		if (fd < 0 && errno == ENOENT) {
			uint8_t *passphrase2;
			size_t pplen2;

			/* input for master password again to check */
			readpass("verify:", &passphrase2, &pplen2);
			if (pplen != pplen2 || memcmp(passphrase, passphrase2, pplen)) {
				fprintf(stderr, "password mismatch\n");
				return -1;
			}

			fd = open(MASTER, O_RDWR | O_CREAT | O_EXCL, 0600);
			if (fd < 0)
				err(1, "%s", MASTER);

			randombytes_buf(s.salt, sizeof(s.salt));
			deriv((char *)passphrase, &s);

			xwrite(fd, s.salt, sizeof(s.salt));
			writepass(&s, passphrase, pplen, fd);
		} else {
			xread(fd, s.salt, sizeof(s.salt), NULL);
			deriv((char *)passphrase, &s);
		}

		haskey = 1;
	}

	/* try to decrypt master password first, to ensure passphrase match */
	lseek(fd, sizeof(s.salt), SEEK_SET);
	if (trydecrypt(&s, fd) < 0) {
		fprintf(stderr, "incorrect master password\n");
		close(fd);
		return -1;
	}
	close(fd);

	if (pflag) {
		if (!sockp)
			return -1;

		return pushkey(&s, sockp);
	}

	secret = argv[0];

	if (aflag) {
		mkdir_p(dirname(secret), 0700);
		fd = open(secret, O_WRONLY | O_CREAT | O_EXCL, 0600);
		if (fd < 0)
			err(1, "%s", secret);

		xwrite(fd, s.salt, sizeof(s.salt));
		writesecret(&s, STDIN_FILENO, fd);
		close(fd);
	} else {
		fd = open(secret, O_RDONLY);
		if (fd < 0)
			err(1, "%s", secret);

		/* Read salt from the beginning of the file */
		lseek(fd, sizeof(s.salt), SEEK_SET);
		readsecret(&s, fd, STDOUT_FILENO);
		close(fd);
	}

	return 0;
}
