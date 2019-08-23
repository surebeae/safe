#include <sys/resource.h>
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
#include "strlcpy.h"

#define SOCKDIR "/tmp/safe-XXXXXX"
#define SOCKET  "agent"

struct safe {
	int loaded;
	uint8_t saltkey[crypto_secretstream_xchacha20poly1305_KEYBYTES + crypto_pwhash_SALTBYTES];
};

char *argv0;
struct safe s;
char *sockp = NULL;
int verbose = 0;

void
usage(void)
{
	fprintf(stderr, "usage: %s [-hdv] [-t timeout] [-f socket]\n", argv0);
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
	strlcpy(addr.sun_path, sockpath, sizeof(addr.sun_path));

	if (bind(sfd, (struct sockaddr *) &addr, sizeof(addr)) < 0)
		return -1;

	if (listen(sfd, 10) < 0)
		return -1;

	return sfd;
}

void
forgetkey()
{
	sodium_memzero(s.saltkey, sizeof(s.saltkey));
	s.loaded = 0;
	alarm(0);
}

void
sighandler(int signal)
{
	switch (signal) {
	case SIGINT:
	case SIGTERM:
		if (verbose)
			fprintf(stderr, "unlocking key from memory\n");
		sodium_munlock(s.saltkey, sizeof(s.saltkey));

		if (verbose)
			fprintf(stderr, "removing socket %s\n", sockp);
		unlink(sockp);
		rmdir(dirname(sockp));
		exit(0);
		/* NOTREACHED */
	case SIGALRM:
	case SIGUSR1:
		if (verbose)
			fprintf(stderr, "clearing key from memory\n");
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

	if (verbose)
		fprintf(stderr, "listening on %s\n", sockp);
	sfd = creatsock(sockp);
	if (sfd < 0)
		err(1, "%s", sockp);

	s.loaded = 0;

	for (;;) {
		pfd.fd = accept(sfd, NULL, NULL);
		pfd.revents = 0;
		pfd.events = POLLIN;

		if (s.loaded)
			pfd.events |= POLLOUT;

		if (pfd.fd < 0)
			err(1, "%s", sockp);

		if ((r = poll(&pfd, 1, 100)) < 0)
			return r;

		if (pfd.revents & POLLIN) {
			if (verbose)
				fprintf(stderr, "reading key from client fd %d\n", pfd.fd);

			n = xread(pfd.fd, s.saltkey, sizeof(s.saltkey));
			if (n == sizeof(s.saltkey)) {
				s.loaded = 1;
				if (verbose) {
					fprintf(stderr, "key loaded in memory\n");
					if (timeout > 0)
						fprintf(stderr, "setting timeout to %d seconds\n", timeout);
				}
				alarm(timeout);
			} else {
				forgetkey();
				if (verbose)
					fprintf(stderr, "failed to load key in memory\n");
			}
		} else if (pfd.revents & POLLOUT) {
			if (verbose)
				fprintf(stderr, "sending key to client fd %d\n", pfd.fd);

			xwrite(pfd.fd, s.saltkey, sizeof(s.saltkey));
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
	int fd, timeout = 0, dflag = 0;
	size_t dirlen;
	char path[PATH_MAX] = SOCKDIR;
	struct rlimit rlim;

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
	case 'v':
		verbose = 1;
		break;
	default:
		usage();
	} ARGEND

	if (sockp) {
		strlcpy(path, sockp, sizeof(path));
	} else {
		if (!mkdtemp(path))
			err(1, "mkdtemp: %s", path);

		dirlen = strnlen(path, sizeof(path));
		snprintf(path + dirlen, PATH_MAX - dirlen, "/%s.%d", SOCKET, pid);
		sockp = path;
	}

	/* deny core dump as memory contains derivated key */
	rlim.rlim_cur = rlim.rlim_max = 0;
	if (setrlimit(RLIMIT_CORE, &rlim) < 0)
		err(1, "setrlimit RLIMIT_CORE");

	if (dflag) {
		printf("SAFE_PID=%d; export SAFE_PID\n", pid);
		printf("SAFE_SOCK=%s; export SAFE_SOCK\n", sockp);
		fflush(stdout);
		goto skip;
	}

	if (verbose)
		fprintf(stderr, "forking agent to the background\n");

	pid = fork();
	if (pid < 0)
		err(1, "fork");

	if (pid) {
		if (verbose)
			fprintf(stderr, "agent pid is %d\n", pid);

		printf("SAFE_PID=%d; export SAFE_PID\n", pid);
		printf("SAFE_SOCK=%s; export SAFE_SOCK\n", sockp);
		return 0;
	}

	if (setsid() < 0)
		err(1, "setsid");

	chdir("/");
	if ((fd = open("/dev/null", O_RDWR, 0)) != -1) {
		(void)dup2(fd, STDIN_FILENO);
		(void)dup2(fd, STDOUT_FILENO);
		(void)dup2(fd, STDERR_FILENO);
		if (fd > 2)
			close(fd);
	}

skip:
	pid = getpid();
	signal(SIGINT, sighandler);
	signal(SIGTERM, sighandler);
	signal(SIGUSR1, sighandler);
	signal(SIGALRM, sighandler);

	if (sodium_init() < 0)
		return -1;

	if (verbose)
		fprintf(stderr, "locking key in memory\n");
	sodium_mlock(s.saltkey, sizeof(s.saltkey));

	return servekey(timeout);
}
