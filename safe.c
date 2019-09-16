#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <paths.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sodium.h>

#include "arg.h"
#include "readpassphrase.h"

#define ASKPASS "thingaskpass"
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

uint8_t *passphrase = NULL;
size_t pplen = 0;
char *argv0;

void
usage(void)
{
	fprintf(stderr, "usage: %s [-hr] [-s safe] [-p prompt] [[-a] entry]\n", argv0);
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

char *
spawn_askpass(const char *askpass, const char *msg, char *buf, size_t bufsiz)
{
	pid_t pid, ret;
	int p[2], eof, status;

	if (!askpass) {
		sodium_memzero(buf, bufsiz);
		return buf;
	}

	if (pipe(p) < 0)
		return NULL;

	pid = fork();
	if (pid < 0)
		return NULL;

	if (!pid) {
		close(p[0]);
		if (dup2(p[1], STDOUT_FILENO) < 0)
			return NULL;

		execlp(askpass, askpass, msg, NULL);
		err(1, "execlp(%s)", askpass); /* NOTREACHED */
	}
	close(p[1]);

	xread(p[0], buf, bufsiz - 1, &eof);
	close(p[0]);

	ret = waitpid(pid, &status, 0);

	if (ret < 0 || !WIFEXITED(status) || WEXITSTATUS(status)) {
		sodium_memzero(buf, bufsiz);
		return buf;
	}

	buf[strcspn(buf, "\r\n")] = '\0';
	return buf;
}

int
readpass(const char *prompt, uint8_t **target, size_t *len, int askflag)
{
	char pass[BUFSIZ], *askpass, *p;
	if (askflag) {
		askpass = ASKPASS;
		if (getenv("SAFE_ASKPASS"))
			askpass = getenv("SAFE_ASKPASS");
		p = spawn_askpass(askpass, prompt, pass, sizeof(pass));
		if (!p)
			err(1, "askpass:");
	} else {
		p = readpassphrase(prompt, pass, sizeof(pass), RPP_ECHO_OFF|RPP_REQUIRE_TTY);
		if (!p)
			err(1, "readpassphrase:");
	}

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
	int r = 0, eof = 0;
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

	sodium_mlock(m, sizeof(m));
	while ((n = xread(fd, c, sizeof(c), &eof)) > 0) {
		if (crypto_secretstream_xchacha20poly1305_pull(&st, m, &mlen, &tag, c, n, NULL, 0))
			r--;

		if (eof && tag != crypto_secretstream_xchacha20poly1305_TAG_FINAL)
			r--;
	}
	sodium_munlock(m, sizeof(m));
	return r;
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
	int fd, haskey = 0, hasmaster = 1, aflag = 0, rflag = 0, kflag = 0, ttyfd;
	char *prompt, *secret, *sockp, *safe = SAFE;
	struct safe s;
	struct rlimit rlim;

	safe   = getenv("SAFE_DIR");
	sockp  = getenv("SAFE_SOCK");
	prompt = "password:";

	ARGBEGIN {
	case 'a':
		aflag = 1;
		break;
	case 'p':
		prompt = EARGF(usage());
		break;
	case 'r':
		rflag = 1;
		break;
	case 's':
		safe = EARGF(usage());
		break;
	case 'k':
		kflag = 1;
		break;
	default:
		usage();
	} ARGEND

	if (argc != 1 && !rflag)
		usage();

	if (sodium_init() < 0)
		return -1;

	sodium_mlock(s.key, sizeof(s.key));

	/* deny core dump as memory contains passwords and keys */
	rlim.rlim_cur = rlim.rlim_max = 0;
	if (setrlimit(RLIMIT_CORE, &rlim) < 0)
		err(1, "setrlimit RLIMIT_CORE");

	if (!safe)
		safe = SAFE;

	mkdir(safe, 0700);
	if (chdir(safe) < 0)
		err(1, "chdir: %s", safe);

	/* open master password as read only to retrieve salt */
	fd = open(MASTER, O_RDONLY);
	if (fd < 0) {
		if (errno != ENOENT)
			err(1, "%s", MASTER);
		hasmaster = 0;
	}

	if (sockp && !readkey(&s, sockp))
		haskey = 1;

	/*
	 * read passphrase from an ASKPASS program stdout if there is
	 * no tty available
	 */
	if ((ttyfd = open(_PATH_TTY, O_RDWR)) < 0)
		kflag = 1;
	else
		close(ttyfd);

	if (!haskey) {
		if (readpass(prompt, &passphrase, &pplen, kflag) < 0)
			return -1;

		sodium_mlock(passphrase, pplen);

		/* write master password entry if not present */
		if (!hasmaster) {
			uint8_t *passphrase2 = NULL;
			size_t pplen2 = 0;

			/* input for master password again to check */
			if (readpass("verify:", &passphrase2, &pplen2, kflag) < 0)
				return -1;

			sodium_mlock(passphrase2, pplen2);

			if (pplen != pplen2 || memcmp(passphrase, passphrase2, pplen)) {
				fprintf(stderr, "password mismatch\n");
				return -1;
			}
			sodium_munlock(passphrase2, pplen2);

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

		sodium_munlock(passphrase, pplen);
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

	/* push the key to a running agent */
	if (rflag) {
		if (!sockp) {
			fprintf(stderr, "SAFE_SOCK variable is not set\n");
			return -1;
		}
		pushkey(&s, sockp);
	}

	secret = argv[0];

	if (!secret)
		return 0;

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

	sodium_munlock(s.key, sizeof(s.key));

	return 0;
}
