#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>

#include <err.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sodium.h>

#include "arg.h"

#define SOCKDIR "/tmp/safe-XXXXXX"
#define SOCKET  "agent"

struct safe {
	int loaded;
	uint8_t saltkey[crypto_secretstream_xchacha20poly1305_KEYBYTES + crypto_pwhash_SALTBYTES];
};

int loop = 1;
char *argv0;
struct safe s;
char *sockp = NULL;

void
usage(void)
{
	fprintf(stderr, "usage: %s [-hd] [-t timeout] [-f socket]\n", argv0);
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

int
creatsock(char *sockpath)
{
	int sfd;
	struct sockaddr_un addr;

	sfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sfd < 0)
		return -1;

	umask(0177);
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, sockpath);

	if (bind(sfd, (struct sockaddr *) &addr, sizeof(addr)) < 0)
		return -1;

	if (listen(sfd, 10) < 0)
		return -1;

	return sfd;
}

void
forgetkey()
{
	memset(s.saltkey, 0, sizeof(s.saltkey));
	s.loaded = 0;
	alarm(0);
	fprintf(stderr, "memory cleared\n");
}

void
sighandler(int signal)
{
	switch (signal) {
	case SIGINT:
	case SIGTERM:
		unlink(sockp);
		rmdir(dirname(sockp));
		exit(0);
		/* NOTREACHED */
	case SIGALRM:
	case SIGUSR1:
		forgetkey();
		break;
	}
}

int
servekey(int timeout)
{
	int r, sfd;
	ssize_t n;
	struct pollfd pfd;

	sfd = creatsock(sockp);
	if (sfd < 0)
		err(1, "%s", sockp);

	s.loaded = 0;

	for (;;) {
		pfd.fd = accept(sfd, NULL, NULL);
		pfd.events = POLLIN|POLLOUT|POLLERR;

		if (pfd.fd < 0)
			err(1, "%s", sockp);

		if ((r = poll(&pfd, 1, 0)) < 1)
			return r;

		if (pfd.revents & POLLOUT) {
			n = s.loaded ? sizeof(s.saltkey) : 0;
			xwrite(pfd.fd, s.saltkey, n);
		}

		if (pfd.revents & POLLIN) {
			n = xread(pfd.fd, s.saltkey, sizeof(s.saltkey));
			if (n == sizeof(s.saltkey)) {
				s.loaded = 1;
				alarm(timeout);
			}
		}
		close(pfd.fd);
	}

	/* NOTREACHED */
	close(sfd);

	return 0;
}

int
main(int argc, char *argv[])
{
	pid_t pid;
	int dflag, timeout;
	size_t dirlen;
	char path[PATH_MAX] = SOCKDIR;

	pid = getpid();

	ARGBEGIN {
	case 'd':
		dflag = 1;
		break;
	case 'f':
		sockp = EARGF(usage());
		break;
	case 't':
		timeout = atoi(EARGF(usage()));
		break;
	default:
		usage();
	} ARGEND

	if (sockp) {
		strncpy(path, sockp, sizeof(path));
	} else {
		if (!mkdtemp(path))
			err(1, "mkdtemp: %s", path);

		dirlen = strnlen(path, sizeof(path));
		snprintf(path + dirlen, PATH_MAX - dirlen, "/%s.%d", SOCKET, pid);
		sockp = path;
	}

	printf("SAFE_PID=%d\n", pid);
	printf("SAFE_SOCK=%s\n", sockp);
	printf("export SAFE_PID SAFE_SOCK\n");
	fflush(stdout);

	if (!dflag)
		daemon(0, 0);

	signal(SIGINT, sighandler);
	signal(SIGTERM, sighandler);
	signal(SIGUSR1, sighandler);
	signal(SIGALRM, sighandler);

	return servekey(timeout);
}
