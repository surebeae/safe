#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

#include <err.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sodium.h>

#include "arg.h"
#include "readpassphrase.h"

#define MDSIZ crypto_generichash_BYTES
#define SOCKET "/tmp/safe.sock"

uint8_t *passphrase;
uint32_t pplen;
char *argv0;

void
usage(void)
{
	fprintf(stderr, "usage: %s [-hf] [-s socket]\n", argv0);
	exit(1);
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
hash(uint8_t *buf, size_t size, uint8_t *md, size_t mdsize)
{
	crypto_generichash(md, mdsize, buf, size, NULL, 0);
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

int
servekey(char *path)
{
	int cfd, sfd;
	char hex[MDSIZ*2 +1];
	uint8_t md[MDSIZ];
	uint8_t salt[crypto_pwhash_SALTBYTES];
	uint8_t key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
	struct sockaddr_un addr;

	readpass("Passphrase:", &passphrase, &pplen);

	hash(passphrase, pplen, md, sizeof(md));
	sodium_memzero(passphrase, pplen);
	sodium_bin2hex(hex, sizeof(hex), md, sizeof(md));

	sfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sfd < 0)
		err(1, "socket: %s", path);

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, path);

	if (bind(sfd, (struct sockaddr *) &addr, sizeof(addr)) < 0)
		err(1, "bind: %s", path);

	listen(sfd, 10);

	while ((cfd = accept(sfd, NULL, NULL)) > 0) {
		xread(cfd, salt, sizeof(salt));
		deriv(hex, salt, key, sizeof(key));
		xwrite(cfd, key, sizeof(key));
		close(cfd);
	}

	close(sfd);

	return 0;
}

int
main(int argc, char *argv[])
{
	char *socket = SOCKET;

	ARGBEGIN {
	case 's':
		socket = EARGF(usage());
		break;
	default:
		usage();
	} ARGEND

	servekey(socket);

	return 0;
}
