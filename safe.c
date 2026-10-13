#include <netinet/in.h>
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
#include "config.h"

struct safe_buffer {
	ssize_t sz;
	uint8_t *buf;
};

struct crypto {
        uint8_t  magic[6];
        uint16_t version;
        uint32_t xchacha20poly1305_bufsiz;
        uint32_t argon2id_memory;
        uint32_t argon2id_time;
        uint32_t argon2id_threads;
	uint8_t  salt[crypto_pwhash_SALTBYTES];
};

struct crypto crypto_defaults = {
	.magic = {'C','R','E','A','M','\1'},
	.version = 0x10,
	.xchacha20poly1305_bufsiz = BUFSIZ, /* must match size in readsecret() and writesecret() */
	.argon2id_memory          = crypto_pwhash_argon2id_MEMLIMIT_INTERACTIVE/1024,
	.argon2id_time            = crypto_pwhash_argon2id_OPSLIMIT_INTERACTIVE,
	.argon2id_threads         = 1, /* not used, hardcoded in libsodium */
};

struct safe {
	uint8_t key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
	struct crypto crypto;
	struct safe_buffer cipher;
	struct safe_buffer message;
};

enum {
	SAFE_INIT  = 1 << 1,
	SAFE_FINAL = 1 << 2,
};

char *argv0;

void
usage(void)
{
	fprintf(stderr, "usage: %s [-bhr] [-s safe] [-p prompt] [[-af] entry]\n", argv0);
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

void *
xmalloc(size_t sz)
{
	void *b = NULL;
	b = malloc(sz);
	if (!b)
		err(1, "malloc");
	return b;
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

struct safe_buffer *
safe_alloc(struct safe_buffer *b, ssize_t nbytes)
{
	b->buf = xmalloc(nbytes);
	b->sz = nbytes;
	sodium_mlock(b->buf, b->sz);
	return b;
}

void
safe_release(struct safe_buffer *b)
{
	if (!b)
		return;

	sodium_memzero(b->buf, b->sz);
	free(b->buf);
	b->buf = NULL;
	b->sz = 0;
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
readpass(const char *prompt, char *buf, size_t bufsiz, int askflag, int stdinflag)
{
	char *askpass;
	if (askflag) {
		askpass = askpass_path;
		if (getenv("SAFE_ASKPASS"))
			askpass = getenv("SAFE_ASKPASS");
		if (!spawn_askpass(askpass, prompt, buf, bufsiz))
			err(1, "askpass:");
	} else {
		int flags = 0;
		flags |= RPP_ECHO_OFF;
		flags |= stdinflag ? RPP_STDIN : RPP_REQUIRE_TTY;
		if (!readpassphrase(prompt, buf, bufsiz, flags))
			err(1, "readpassphrase:");
	}

	if (buf[0] == '\0')
		return -1;

	return strnlen(buf, bufsiz);
}

void
deriv(char *pw, struct safe *s)
{
	if (crypto_pwhash(s->key, sizeof(s->key), pw, strlen(pw),
			s->crypto.salt, s->crypto.argon2id_time,
			s->crypto.argon2id_memory * 1024,
			crypto_pwhash_ALG_ARGON2ID13))
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

	if (xwrite(sfd, s->crypto.salt, sizeof(s->crypto.salt)) < 0)
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

	if ((n = xread(sfd, &s->crypto.salt, sizeof(s->crypto.salt), NULL)) <= 0)
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
	uint8_t *c = s->cipher.buf;
	uint8_t *m = s->message.buf;
	uint8_t h[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
	crypto_secretstream_xchacha20poly1305_state st;

	xread(fd, h, sizeof(h), NULL);
	if (crypto_secretstream_xchacha20poly1305_init_pull(&st, h, s->key))
		return -1;

	while ((n = xread(fd, c, s->cipher.sz, &eof)) > 0) {
		if (crypto_secretstream_xchacha20poly1305_pull(&st, m, NULL, &tag, c, n, NULL, 0))
			r--;

		if (eof && tag != crypto_secretstream_xchacha20poly1305_TAG_FINAL)
			r--;
	}
	sodium_memzero(m, s->crypto.xchacha20poly1305_bufsiz);
	return r;
}

int
readheader(int fd, struct crypto *hdr)
{
	uint8_t buf[40];
	uint16_t s;
	uint32_t l;

	xread(fd, buf, sizeof(buf), NULL);

        memcpy(hdr->magic, buf +  0, 6);
	memcpy(&s, buf +  6, 2); hdr->version = ntohs(s);
	memcpy(&l, buf +  8, 4); hdr->xchacha20poly1305_bufsiz = ntohl(l);
	memcpy(&l, buf + 12, 4); hdr->argon2id_memory = ntohl(l);
	memcpy(&l, buf + 16, 4); hdr->argon2id_time = ntohl(l);
	memcpy(&l, buf + 20, 4); hdr->argon2id_threads = ntohl(l);
	memcpy(hdr->salt, buf + 24, 16);

	return 0;
}

int
writeheader(int fd, struct crypto hdr)
{
	uint8_t buf[40];
	uint16_t s;
	uint32_t l;

        memcpy(buf +  0, hdr.magic, 6);
        s = htons(hdr.version);                  memcpy(buf +  6, (uint8_t *) &s, 2);
        l = htonl(hdr.xchacha20poly1305_bufsiz); memcpy(buf +  8, (uint8_t *) &l, 4);
        l = htonl(hdr.argon2id_memory);          memcpy(buf + 12, (uint8_t *) &l, 4);
        l = htonl(hdr.argon2id_time);            memcpy(buf + 16, (uint8_t *) &l, 4);
        l = htonl(hdr.argon2id_threads);         memcpy(buf + 20, (uint8_t *) &l, 4);
	memcpy(buf + 24, hdr.salt, 16);

	return xwrite(fd, buf, sizeof(buf));
}

/*
 * This is only used to encrypt the master password when initializing
 * a new safe. Assumes mlen ⇐ xchacha20poly1305_bufsiz, which should
 * be the case as all buffers are initialized to the same length by
 * default (BUF_SIZ).
 */
int
writepass(struct safe *s, char *m, size_t mlen, int fd)
{
	uint8_t h[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
	crypto_secretstream_xchacha20poly1305_state st;
	unsigned long long clen;

	if (mlen > s->crypto.xchacha20poly1305_bufsiz)
		return -1;

	if (crypto_secretstream_xchacha20poly1305_init_push(&st, h, s->key))
		return -1;

	if (crypto_secretstream_xchacha20poly1305_push(&st, s->cipher.buf, &clen, (uint8_t *)m, mlen, NULL, 0, crypto_secretstream_xchacha20poly1305_TAG_FINAL))
		return -1;

	xwrite(fd, h, sizeof(h));
	xwrite(fd, s->cipher.buf, clen);

	return 0;
}

int
writesecret(struct safe *s, int in, int out)
{
	int eof;
	ssize_t n;
	uint8_t tag;
	uint8_t h[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
	crypto_secretstream_xchacha20poly1305_state st;
	unsigned long long clen;

	if (crypto_secretstream_xchacha20poly1305_init_push(&st, h, s->key))
		return -1;

	xwrite(out, h, sizeof(h));

	while ((n = xread(in, s->message.buf, s->message.sz, &eof)) > 0) {
		tag = eof ? crypto_secretstream_xchacha20poly1305_TAG_FINAL : 0;
		if (crypto_secretstream_xchacha20poly1305_push(&st, s->cipher.buf, &clen, s->message.buf, n, NULL, 0, tag))
			return -1;

		xwrite(out, s->cipher.buf, clen);
	}
	return 0;
}

int
readsecret(struct safe *s, int in, int out)
{
	int eof = 0;
	ssize_t n;
	uint8_t tag;
	uint8_t h[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
	crypto_secretstream_xchacha20poly1305_state st;
	unsigned long long mlen;

	xread(in, h, sizeof(h), NULL);
	if (crypto_secretstream_xchacha20poly1305_init_pull(&st, h, s->key))
		return -1;

	while ((n = xread(in, s->cipher.buf, s->cipher.sz, &eof)) > 0) {
		if (crypto_secretstream_xchacha20poly1305_pull(&st, s->message.buf, &mlen, &tag, s->cipher.buf, n, NULL, 0))
			return -1;

		if (eof && tag != crypto_secretstream_xchacha20poly1305_TAG_FINAL)
			return -1;

		xwrite(out, s->message.buf, mlen);
	}
	return 0;
}

int
main(int argc, char *argv[])
{
	int aflag = 0, bflag = 0, rflag = 0, kflag = 0, fflag = 0;
	int fd, haskey = 0, hasmaster = 1, ttyfd;
	char *prompt, *secret, *sockp, *safe = safe_dir;
	char passphrase[BUFSIZ], verifyphrase[BUFSIZ];
	ssize_t pplen, vplen = 0;
	struct safe s;

	safe   = getenv("SAFE_DIR");
	sockp  = getenv("SAFE_SOCK");
	prompt = "password:";

	/* set default cream parameters */
	memcpy(&s.crypto, &crypto_defaults, sizeof(s.crypto));

	ARGBEGIN {
	case 'f':
		fflag = 1;
		/* FALLTHROUGH */
	case 'a':
		aflag = 1;
		break;
	case 'b':
		bflag = 1;
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

	if (!safe)
		safe = safe_dir;

	if (argc != 1 && !rflag)
		usage();

	if (sodium_init() < 0)
		return -1;

	sodium_mlock(&s, sizeof(s));
	sodium_mlock(&passphrase, sizeof(passphrase));
	sodium_mlock(&verifyphrase, sizeof(verifyphrase));

#ifndef _DEBUG
	/* deny core dump as memory contains passwords and keys */
	struct rlimit rlim;
	rlim.rlim_cur = rlim.rlim_max = 0;
	if (setrlimit(RLIMIT_CORE, &rlim) < 0)
		err(1, "setrlimit RLIMIT_CORE");
#endif

	mkdir(safe, 0700);

#ifdef __OpenBSD__
	if (unveil(_PATH_TTY, "rw") == -1)
		err(1, "unveil %s", _PATH_TTY);
	if (unveil(safe, "rwc") == -1)
		err(1, "unveil %s", safe);
	if (sockp)
		if (unveil(sockp, "rw") == -1)
			err(1, "unveil %s", sockp);
	if (pledge("stdio rpath wpath cpath unix tty", NULL) < 0)
		err(1, "pledge");
#endif

	if (chdir(safe) < 0)
		err(1, "chdir: %s", safe);

	/* open master password as read only to retrieve salt */
	fd = open(master_entry, O_RDONLY);
	if (fd < 0) {
		if (errno != ENOENT)
			err(1, "%s", master_entry);
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

	/* write master password entry if not present */
	if (!hasmaster) {
		pplen = readpass(prompt, passphrase, sizeof(passphrase), kflag, bflag);
		if (pplen < 0)
			return -1;

		/* input for master password again to check */
		vplen = readpass("verify:", verifyphrase, sizeof(verifyphrase), kflag, bflag);
		if (vplen < 0)
			return -1;

		if (pplen != vplen || memcmp(passphrase, verifyphrase, pplen)) {
			fprintf(stderr, "password mismatch\n");
			return -1;
		}

		fd = open(master_entry, O_RDWR | O_CREAT | O_EXCL, 0600);
		if (fd < 0)
			err(1, "%s", master_entry);

		randombytes_buf(s.crypto.salt, sizeof(s.crypto.salt));
		deriv((char *)passphrase, &s);

		writeheader(fd, s.crypto);
		writepass(&s, passphrase, pplen, fd);
		haskey = 1;
	}

	if (!haskey) {
		pplen = readpass(prompt, passphrase, sizeof(passphrase), kflag, bflag);
		if (pplen < 0)
			return -1;

		readheader(fd, &s.crypto);
		deriv(passphrase, &s);
		haskey = 1;
	}

	safe_alloc(&s.message, s.crypto.xchacha20poly1305_bufsiz);
	safe_alloc(&s.cipher, s.crypto.xchacha20poly1305_bufsiz + crypto_secretstream_xchacha20poly1305_ABYTES);

	/* try to decrypt master password first, to ensure passphrase match */
	lseek(fd, sizeof(s.crypto), SEEK_SET);
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

		/* Prevent overwriting unless fflag is set */
		fd = open(secret, O_WRONLY | O_CREAT | (fflag ? 0 : O_EXCL), 0600);
		if (fd < 0)
			err(1, "%s", secret);

		writeheader(fd, s.crypto);
		writesecret(&s, STDIN_FILENO, fd);
		close(fd);
	} else {
		fd = open(secret, O_RDONLY);
		if (fd < 0)
			err(1, "%s", secret);

		/* Read salt from the beginning of the file */
		lseek(fd, sizeof(s.crypto), SEEK_SET);
		readsecret(&s, fd, STDOUT_FILENO);
		close(fd);
	}

	sodium_memzero(&s, sizeof(s));
	sodium_memzero(&passphrase, sizeof(passphrase));
	sodium_memzero(&verifyphrase, sizeof(verifyphrase));
	safe_release(&s.message);
	safe_release(&s.cipher);

	return 0;
}
