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

#define SOCKDIR "/tmp/safe-XXXXXX"
#define SOCKET  "agent"
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
creatsock(char *sockpath)
{
	int sfd;
	struct sockaddr_un addr;

	sfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sfd < 0)
		return -1;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, sockpath);

	if (bind(sfd, (struct sockaddr *) &addr, sizeof(addr)) < 0)
		return -1;

	if (listen(sfd, 10) < 0)
		return -1;

	return sfd;
}

int
agent(struct safe *s, char *sockp)
{
	int cfd, sfd;
	pid_t pid;
	size_t dirlen;
	char path[PATH_MAX] = SOCKDIR;

	pid = getpid();

	if (sockp) {
		strncpy(path, sockp, sizeof(path));
	} else {
		if (!mkdtemp(path))
			err(1, "mkdtemp: %s", path);

		dirlen = strnlen(path, sizeof(path));
		snprintf(path + dirlen, PATH_MAX - dirlen, "/%s.%d", SOCKET, pid);
	}

	sfd = creatsock(path);
	if (sfd < 0)
		err(1, "%s", path);

	printf("SAFE_PID=%d\n", pid);
	printf("SAFE_SOCK=%s\n", path);

	while ((cfd = accept(sfd, NULL, NULL)) > 0) {
		xwrite(cfd, s->key, sizeof(s->key));
		close(cfd);
	}

	close(sfd);

	return 0;
}

int
readkey(struct safe *s, char *path)
{
	int sfd;
	struct sockaddr_un addr;

	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, path);

	if ((sfd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
		return -1;

	if (connect(sfd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
		return -1;

	xread(sfd, s->key, sizeof(s->key), NULL);

	return 0;
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

	deriv((char *)passphrase, s);

	c = malloc(mlen + crypto_secretstream_xchacha20poly1305_ABYTES);
	if (!c)
		err(1, "malloc");

	if (crypto_secretstream_xchacha20poly1305_init_push(&st, h, s->key))
		return -1;

	if (crypto_secretstream_xchacha20poly1305_push(&st, c, &clen, m, mlen, NULL, 0, crypto_secretstream_xchacha20poly1305_TAG_FINAL))
		return -1;

	xwrite(fd, s->salt, sizeof(s->salt));
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
	int fd, aflag = 0, dflag = 0;
	char *secret = NULL, *sockp = NULL, *safe = SAFE;
	struct safe s;

	ARGBEGIN {
	case 'a':
		aflag = 1;
		break;
	case 'd':
		dflag = 1;
		break;
	case 'f':
		sockp = EARGF(usage());
		break;
	case 's':
		safe = EARGF(usage());
		break;
	default:
		usage();
	} ARGEND

	if (argc != 1 && !dflag)
		usage();

	if (sodium_init() < 0)
		return -1;

	umask(077);
	if (safe) {
		mkdir(safe, 0700);
		if (chdir(safe) < 0)
			err(1, "chdir: %s", safe);
	}

	if (dflag)
		return agent(&s, sockp);

	secret = argv[0];

	readpass("password:", &passphrase, &pplen);

	/* create master password entry if it doesn't exists */
	fd = open(MASTER, O_WRONLY | O_CREAT | O_EXCL, 0600);
	if (fd < 0) {
		if (errno != EEXIST)
			err(1, "%s", MASTER);
	} else {
		randombytes_buf(s.salt, sizeof(s.salt));
		deriv((char *)passphrase, &s);
		writepass(&s, passphrase, pplen, fd);
		close(fd);
	}

	if (aflag) {
		fd = open(MASTER, O_RDONLY);
		if (fd < 0)
			err(1, "%s", MASTER);
		xread(fd, s.salt, sizeof(s.salt), NULL);
		deriv((char *)passphrase, &s);

		/* do not store secret if master password mismatch */
		if (trydecrypt(&s, fd) < 0) {
			fprintf(stderr, "incorrect master password\n");
			close(fd);
			return -1;
		}
		close(fd);

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
		xread(fd, s.salt, sizeof(s.salt), NULL);
		deriv((char *)passphrase, &s);
		readsecret(&s, fd, STDOUT_FILENO);
		close(fd);
	}

	return 0;
}
