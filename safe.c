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
#include "readpassphrase.h"

#define CKSIZE 4096
#define MDSIZE crypto_generichash_BYTES
#define SAFE ".secrets"

char *argv0;

uint8_t *passphrase;
uint32_t pplen;

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
deriv(char *pw, uint8_t *salt, uint8_t *key, size_t ks)
{
	if (crypto_pwhash(key, ks, pw, strlen(pw),
			salt, crypto_pwhash_OPSLIMIT_INTERACTIVE,
			crypto_pwhash_MEMLIMIT_INTERACTIVE,
			crypto_pwhash_ALG_DEFAULT))
		err(1, "crypto_pwhash");
}

void
xencrypt(int ifd, int ofd, uint8_t *key)
{
	ssize_t n;
	uint8_t in[CKSIZE];
	uint8_t out[CKSIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
	uint8_t hdr[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
	crypto_secretstream_xchacha20poly1305_state st;
	unsigned long long len;

	crypto_secretstream_xchacha20poly1305_init_push(&st, hdr, key);
	xwrite(ofd, hdr, sizeof(hdr));

	while ((n = xread(ifd, in, sizeof(in))) > 0) {
		if ((size_t) n < sizeof(in))
			break;

		crypto_secretstream_xchacha20poly1305_push(&st, out, &len, in, n, NULL, 0, 0);
		xwrite(ofd, out, len);
	}

	if (n < 0)
		err(1, "xencrypt");

	crypto_secretstream_xchacha20poly1305_push(&st, out, &len, in, n, NULL, 0, crypto_secretstream_xchacha20poly1305_TAG_FINAL);
	xwrite(ofd, out, len);
}

void
xdecrypt(int ifd, int ofd, uint8_t *key)
{
	ssize_t n;
	uint8_t out[CKSIZE];
	uint8_t in[CKSIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
	uint8_t hdr[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
	crypto_secretstream_xchacha20poly1305_state st;
	unsigned long long len;

	xread(ifd, hdr, sizeof(hdr));
	if (crypto_secretstream_xchacha20poly1305_init_pull(&st, hdr, key)) {
		fprintf(stderr, "decrypt: incomplete header\n");
		exit(1);
	}

	while ((n = xread(ifd, in, sizeof(in))) > 0) {
		crypto_secretstream_xchacha20poly1305_pull(&st, out,
		                                           &len, NULL, in, n,
		                                           NULL, 0);
		xwrite(ofd, out, len);
	}
}

int
store_secret(int fd, char *name)
{
	int sfd;
	uint8_t key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
	uint8_t salt[crypto_pwhash_SALTBYTES];

	mkdir_p(dirname(name), 0700);
	sfd = open(name, O_WRONLY | O_CREAT, 0600);
	if (sfd < 0)
		err(1, "open %s", name);

	randombytes_buf(salt, sizeof(salt));
	xwrite(sfd, salt, sizeof(salt));

	readpass("Passphrase:", &passphrase, &pplen);
	deriv((char *)passphrase, salt, key, sizeof(key));

	xencrypt(fd, sfd, key);
	close(sfd);

	return 0;
}

int
show_secret(int fd, char *name)
{
	int sfd;
	uint8_t key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
	uint8_t salt[crypto_pwhash_SALTBYTES];

	sfd = open(name, O_RDONLY);
	if (sfd < 0)
		err(1, "open %s", name);

	xread(sfd, salt, sizeof(salt));

	readpass("Passphrase:", &passphrase, &pplen);
	deriv((char *)passphrase, salt, key, sizeof(key));

	xdecrypt(sfd, fd, key);
	close(sfd);

	return 0;
}

int
main(int argc, char *argv[])
{
	int aflag = 0, lflag = 0;
	char *secret = NULL, *safe = SAFE;

	ARGBEGIN {
	case 'a':
		aflag = 1;
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

	secret = argv[0];

	if (aflag) {
		store_secret(STDIN_FILENO, secret);
	} else {
		show_secret(STDOUT_FILENO, secret);
	}

	return 0;
}
