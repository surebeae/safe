#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>

#include <err.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <paths.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sodium.h>

#include "arg.h"
#include "config.h"
#include "proto.h"

#ifdef __linux__
# include <sys/syscall.h>
# ifndef SYS_openat2
#  define SYS_openat2 437
# endif
# ifndef __NR_openat2
#  define __NR_openat2 437
# endif
#endif


#if defined(__linux__) && !defined(_DEBUG) && defined(SAFE_SANDBOX) && SAFE_SANDBOX
# if defined(__x86_64__) || defined(__aarch64__)
#  define SANDBOX 1
# else
#  warning "no seccomp filter for this architecture; building without sandbox"
# endif
#endif

#ifdef SANDBOX
# include <linux/audit.h>
# include <linux/filter.h>
# include <linux/seccomp.h>
# include <sys/prctl.h>
# include <sys/syscall.h>
# ifndef SYS_landlock_create_ruleset
#  define SYS_landlock_create_ruleset 444
# endif
# ifndef SYS_landlock_add_rule
#  define SYS_landlock_add_rule 445
# endif
# ifndef SYS_landlock_restrict_self
#  define SYS_landlock_restrict_self 446
# endif

struct landlock_ruleset_attr { uint64_t handled_access_fs; };
struct landlock_path_beneath_attr {
	uint64_t allowed_access;
	int32_t  parent_fd;
} __attribute__((packed));

#ifndef LANDLOCK_RULE_PATH_BENEATH
# define LANDLOCK_RULE_PATH_BENEATH 1
#endif
#ifndef LANDLOCK_ACCESS_FS_EXECUTE
# define LANDLOCK_ACCESS_FS_EXECUTE     (1ULL << 0)
# define LANDLOCK_ACCESS_FS_WRITE_FILE  (1ULL << 1)
# define LANDLOCK_ACCESS_FS_READ_FILE   (1ULL << 2)
# define LANDLOCK_ACCESS_FS_READ_DIR    (1ULL << 3)
# define LANDLOCK_ACCESS_FS_REMOVE_DIR  (1ULL << 4)
# define LANDLOCK_ACCESS_FS_REMOVE_FILE (1ULL << 5)
# define LANDLOCK_ACCESS_FS_MAKE_CHAR   (1ULL << 6)
# define LANDLOCK_ACCESS_FS_MAKE_DIR    (1ULL << 7)
# define LANDLOCK_ACCESS_FS_MAKE_REG    (1ULL << 8)
# define LANDLOCK_ACCESS_FS_MAKE_SOCK   (1ULL << 9)
# define LANDLOCK_ACCESS_FS_MAKE_FIFO   (1ULL << 10)
# define LANDLOCK_ACCESS_FS_MAKE_BLOCK  (1ULL << 11)
# define LANDLOCK_ACCESS_FS_MAKE_SYM    (1ULL << 12)
#endif

static int
landlock_add_path(int ruleset, const char *path, uint64_t access)
{
	struct landlock_path_beneath_attr pb;
	int fd, rc;

	fd = open(path, O_PATH | O_CLOEXEC);
	if (fd < 0)
		return -1;
	pb.allowed_access = access;
	pb.parent_fd = fd;
	rc = syscall(SYS_landlock_add_rule, ruleset,
	    LANDLOCK_RULE_PATH_BENEATH, &pb, 0);
	close(fd);
	return rc;
}

static int
install_landlock(const char *sock_dir, const char *store_dir,
    int allow_rmdir)
{

	struct landlock_ruleset_attr ra = {0};
	uint64_t handled =
	    LANDLOCK_ACCESS_FS_EXECUTE     | LANDLOCK_ACCESS_FS_WRITE_FILE |
	    LANDLOCK_ACCESS_FS_READ_FILE   | LANDLOCK_ACCESS_FS_READ_DIR   |
	    LANDLOCK_ACCESS_FS_REMOVE_DIR  | LANDLOCK_ACCESS_FS_REMOVE_FILE |
	    LANDLOCK_ACCESS_FS_MAKE_CHAR   | LANDLOCK_ACCESS_FS_MAKE_DIR   |
	    LANDLOCK_ACCESS_FS_MAKE_REG    | LANDLOCK_ACCESS_FS_MAKE_SOCK  |
	    LANDLOCK_ACCESS_FS_MAKE_FIFO   | LANDLOCK_ACCESS_FS_MAKE_BLOCK |
	    LANDLOCK_ACCESS_FS_MAKE_SYM;
	char parent[PATH_MAX];
	char xdg_safe[PATH_MAX];
	const char *xdg;
	char *slash;
	int ruleset, rc;

	ra.handled_access_fs = handled;
	ruleset = syscall(SYS_landlock_create_ruleset, &ra, sizeof(ra), 0);
	if (ruleset < 0) {
		if (errno == ENOSYS || errno == EOPNOTSUPP) {
			if (getenv("SAFE_ALLOW_NO_LANDLOCK")) {
				warnx("Landlock unavailable, continuing without it");
				return 0;
			}
			warnx("Landlock unavailable (set SAFE_ALLOW_NO_LANDLOCK=1 "
			    "to run without it)");
		}
		return -1;
	} 

	if (sock_dir && *sock_dir) {
		if (landlock_add_path(ruleset, sock_dir,
		    LANDLOCK_ACCESS_FS_READ_DIR   |
		    LANDLOCK_ACCESS_FS_READ_FILE  |
		    LANDLOCK_ACCESS_FS_WRITE_FILE |
		    LANDLOCK_ACCESS_FS_MAKE_REG   |
		    LANDLOCK_ACCESS_FS_MAKE_SOCK  |
		    LANDLOCK_ACCESS_FS_REMOVE_FILE) < 0) {
			close(ruleset);
			return -1;
		}

		snprintf(parent, sizeof(parent), "%s", sock_dir);
		slash = strrchr(parent, '/');
		if (allow_rmdir && slash && slash != parent) {
			*slash = 0;
			landlock_add_path(ruleset, parent,
			    LANDLOCK_ACCESS_FS_REMOVE_DIR);
		}
	}


	if (store_dir && *store_dir) {
		if (landlock_add_path(ruleset, store_dir,
		    LANDLOCK_ACCESS_FS_READ_FILE |
		    LANDLOCK_ACCESS_FS_READ_DIR) < 0) {
			close(ruleset);
			return -1;
		}
	}


	xdg = getenv("XDG_RUNTIME_DIR");
	if (xdg && *xdg) {
		if (snprintf(xdg_safe, sizeof xdg_safe, "%s/safe", xdg)
		    < (int)sizeof xdg_safe) {
			mkdir(xdg_safe, 0700);  
			landlock_add_path(ruleset, xdg_safe,
			    LANDLOCK_ACCESS_FS_READ_FILE   |
			    LANDLOCK_ACCESS_FS_WRITE_FILE  |
			    LANDLOCK_ACCESS_FS_MAKE_REG    |
			    LANDLOCK_ACCESS_FS_REMOVE_FILE |
			    LANDLOCK_ACCESS_FS_READ_DIR);
		}
	}

	landlock_add_path(ruleset, _PATH_DEVNULL,
	    LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_WRITE_FILE);

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
		close(ruleset);
		return -1;
	}
	rc = syscall(SYS_landlock_restrict_self, ruleset, 0);
	close(ruleset);
	return rc < 0 ? -1 : 0;
}

static int
install_seccomp(void)
{
	struct sock_filter f[512];
	unsigned short i = 0;


#define N_FILTER ((int)(sizeof(f) / sizeof(f[0])))
#define RET(k) do { if (i >= N_FILTER) return -1; f[i++] = (struct sock_filter)BPF_STMT(BPF_RET|BPF_K, (k)); } while (0)
#define LD(o)  do { if (i >= N_FILTER) return -1; f[i++] = (struct sock_filter)BPF_STMT(BPF_LD|BPF_W|BPF_ABS, (o)); } while (0)
#define JEQ(k,jt,jf) do { if (i >= N_FILTER) return -1; f[i++] = (struct sock_filter)BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, (k), (jt), (jf)); } while (0)
#define A(nr)  do { JEQ((nr), 0, 1); RET(SECCOMP_RET_ALLOW); } while (0)
#define AS(n)  do { A(__NR_##n); } while (0)

	LD(offsetof(struct seccomp_data, arch));
#if defined(__x86_64__)
	JEQ(AUDIT_ARCH_X86_64, 1, 0);
#elif defined(__aarch64__)
	JEQ(AUDIT_ARCH_AARCH64, 1, 0);
#else
	return -1;
#endif
	RET(SECCOMP_RET_KILL_PROCESS);

	LD(offsetof(struct seccomp_data, nr));

	JEQ(__NR_socket, 0, 4);
	LD(offsetof(struct seccomp_data, args[0]));
	JEQ(AF_UNIX, 1, 0);
	RET(SECCOMP_RET_KILL_PROCESS);
	RET(SECCOMP_RET_ALLOW);

#ifdef __NR_socketpair
	JEQ(__NR_socketpair, 0, 4);
	LD(offsetof(struct seccomp_data, args[0]));
	JEQ(AF_UNIX, 1, 0);
	RET(SECCOMP_RET_KILL_PROCESS);
	RET(SECCOMP_RET_ALLOW);
#endif

	JEQ(__NR_prctl, 0, 5);
	LD(offsetof(struct seccomp_data, args[0]));
	JEQ(PR_SET_NO_NEW_PRIVS, 2, 0);
	JEQ(PR_SET_SECCOMP, 1, 0);
	RET(SECCOMP_RET_KILL_PROCESS);
	RET(SECCOMP_RET_ALLOW);

        AS(read); AS(write); AS(close); AS(lseek);
        AS(pread64); AS(pwrite64); AS(readv); AS(writev);
        AS(openat);
#ifdef __NR_openat2
        AS(openat2);
#endif
#ifdef __NR_open
	AS(open);
#endif
	AS(newfstatat); AS(fstat);
#ifdef __NR_stat
	AS(stat);
#endif
#ifdef __NR_lstat
	AS(lstat);
#endif
	AS(statx);
#ifdef __NR_unlink
	AS(unlink);
#endif
	AS(unlinkat);
#ifdef __NR_rmdir
	AS(rmdir);
#endif
#ifdef __NR_rename
	AS(rename);
#endif
#ifdef __NR_renameat
	AS(renameat);
#endif
#ifdef __NR_renameat2
	AS(renameat2);
#endif
#ifdef __NR_mkdir
	AS(mkdir);
#endif
	AS(mkdirat);
	AS(chdir); AS(fchdir); AS(getcwd);
	AS(getdents64);
	AS(fcntl);

	AS(mmap); AS(munmap); AS(mprotect); AS(mremap); AS(madvise);
	AS(brk); AS(mlock); AS(munlock);

	AS(rt_sigaction); AS(rt_sigprocmask); AS(rt_sigreturn);
	AS(sigaltstack); AS(tgkill);
#ifdef __NR_poll
	AS(poll);
#endif
	AS(ppoll);
#ifdef __NR_alarm
	AS(alarm);
#endif
	AS(setitimer); AS(getitimer);

	AS(getpid); AS(getppid); AS(gettid);
	AS(getuid); AS(geteuid); AS(getgid); AS(getegid); AS(getgroups);
	AS(uname);

	AS(set_tid_address); AS(set_robust_list); AS(rseq);
        AS(prlimit64); AS(getrlimit);
	/* no setrlimit: libc uses prlimit64 */
	AS(clock_gettime); AS(clock_nanosleep); AS(nanosleep);
	AS(getrandom); AS(membarrier); AS(futex); AS(sched_yield);

	AS(bind); AS(listen); AS(accept);
	AS(connect); AS(sendto); AS(recvfrom);
	AS(sendmsg); AS(recvmsg); AS(shutdown);
	AS(getsockname); AS(getpeername);
	AS(setsockopt); AS(getsockopt);

#ifdef __NR_sysinfo
	AS(sysinfo);
#endif
#ifdef __NR_umask
	AS(umask);
#endif
#ifdef __NR_pipe2
	AS(pipe2);
#endif
#ifdef __NR_accept4
	AS(accept4);
#endif
#ifdef __NR_sched_getaffinity
	AS(sched_getaffinity);
#endif
#ifdef __NR_sched_setaffinity
	AS(sched_setaffinity);
#endif
#ifdef __NR_getrusage
	AS(getrusage);
#endif
#ifdef __NR_fchmod
	AS(fchmod);
#endif
#ifdef __NR_fchmodat
	AS(fchmodat);
#endif

	AS(exit); AS(exit_group);

#ifdef __NR_arch_prctl
	AS(arch_prctl);
#endif

	RET(SECCOMP_RET_KILL_PROCESS);

#undef A
#undef AS
#undef JEQ
#undef LD
#undef RET
#undef N_FILTER

	struct sock_fprog prog = { .len = i, .filter = f };
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
		return -1;
	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) < 0)
		return -1;
	return 0;
}
#endif 



#include "validate.h"



struct peer_info {
	uid_t uid;
	pid_t pid;
};

static struct peer_info
peer_cred(int fd)
{
	struct peer_info pi = { (uid_t)-1, (pid_t)-1 };

#if defined(__linux__)
	{
		struct ucred cred;
		socklen_t len = sizeof cred;

		if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED,
		    &cred, &len) < 0)
			return pi;
		pi.uid = cred.uid;
		pi.pid = cred.pid;
	}
#else
	{
		uid_t uid;
		gid_t gid;

		if (getpeereid(fd, &uid, &gid) < 0)
			return pi;
		pi.uid = uid;

	}
#endif
	return pi;
}


static int
peer_matches_exe(pid_t pid, const char *expected)
{
	if (!expected || !*expected)
		return 1;
#if !defined(__linux__)
	(void)pid;
	return 0;
#else
	char link[64];
	char exe[PATH_MAX];
	ssize_t n;

	if (pid <= 0)
		return 0;
	if (snprintf(link, sizeof link, "/proc/%d/exe", (int)pid)
	    >= (int)sizeof link)
		return 0;
	n = readlink(link, exe, sizeof exe - 1);
	if (n < 0)
		return 0;
	exe[n] = '\0';
	return strcmp(exe, expected) == 0;
#endif
}


static int
peer_lsm_label(int fd, char *buf, size_t bufsiz)
{
#ifdef SO_PEERSEC
	socklen_t len = (socklen_t)bufsiz;

	if (bufsiz == 0)
		return -1;
	if (getsockopt(fd, SOL_SOCKET, SO_PEERSEC, buf, &len) < 0)
		return -1;
	if (len == 0)
		return -1;
	while (len > 0 && buf[len - 1] == '\0')
		len--;
	if (len == 0 || (size_t)len >= bufsiz)
		return -1;
	buf[len] = '\0';
	return 0;
#else
	(void)fd; (void)buf; (void)bufsiz;
	return -1;
#endif
}



struct safe {
	int loaded;
	int one_shot;
	uint8_t saltkey[crypto_secretstream_xchacha20poly1305_KEYBYTES +
	                crypto_pwhash_SALTBYTES];
};

struct agent_bufs {
	uint8_t *cipher;
	size_t   cipher_sz;
	uint8_t *plain;
	size_t   plain_sz;
};

char *argv0;
struct safe s;
char *sockp = NULL;
int verbose = 0;
static int created_dir = 0;
static char sockpath_buf[PATH_MAX];	
static char sock_dir[PATH_MAX];
static char store_dir[PATH_MAX];
static int store_dirfd = -1;
static uid_t allow_uid = (uid_t)-1;
static int have_allow_uid = 0;
static char prefix[PATH_MAX] = "";
static int have_prefix = 0;
static int socket_relaxed = 0;
static char peer_exe_path[PATH_MAX] = "";
static char peer_sec_label[256] = "";
static char confirm_cmd[PATH_MAX] = "";
static struct agent_bufs ab = { NULL, 0, NULL, 0 };
static volatile sig_atomic_t sig_quit = 0;
static volatile sig_atomic_t sig_forget = 0;

static void
usage(void)
{
	fprintf(stderr,
	    "usage: %s [-hdgv] [-t timeout] [-f socket] [-s storedir]\n"
	    "          [-u uid] [-p prefix] [-e peer-exe] [-c confirm-cmd]\n"
	    "          [-S lsm-label]\n",
	    argv0);
	exit(1);
}

#ifdef __OpenBSD__
static char *
dirname(char *path)
{
	static char tmp[PATH_MAX];
	char *p = NULL;
	size_t len;

	snprintf(tmp, sizeof(tmp), "%s", path);
	len = strlen(tmp);
	for (p = tmp + len; p > tmp; p--)
		if (*p == '/')
			break;
	*p = 0;
	return tmp;
}
#endif

static ssize_t
xwrite(int fd, const void *buf, size_t nbytes)
{
	const uint8_t *bp = buf;
	ssize_t total = 0;

	while (nbytes > 0) {
		ssize_t n = write(fd, &bp[total], nbytes);
		if (n < 0) {
			if (errno == EINTR) {
				if (sig_quit || sig_forget)
					return -1;
				continue;
			}
			return -1;
		} else if (n == 0)
			return total;
		total += n;
		nbytes -= n;
	}
	return total;
}


static int
recv_deadline(int fd, uint8_t *buf, size_t nbytes, int timeout_sec)
{
	struct timespec start, now;
	size_t total = 0;

	clock_gettime(CLOCK_MONOTONIC, &start);
	while (total < nbytes) {
		struct pollfd pfd = { .fd = fd, .events = POLLIN };
		long long remaining_ms;
		long long elapsed_sec;
		long elapsed_nsec;
		int prc;
		ssize_t n;

		clock_gettime(CLOCK_MONOTONIC, &now);

		elapsed_sec = (long long)now.tv_sec - start.tv_sec;
		elapsed_nsec = now.tv_nsec - start.tv_nsec;
		if (elapsed_nsec < 0) {
			elapsed_sec -= 1;
			elapsed_nsec += 1000000000L;
		}
		remaining_ms = (long long)(timeout_sec - elapsed_sec) * 1000LL
		             - (long long)elapsed_nsec / 1000000LL;
		if (remaining_ms <= 0)
			return -1;
		if (remaining_ms > INT_MAX)
			remaining_ms = INT_MAX;
		if (sig_quit || sig_forget)
			return -1;

		prc = poll(&pfd, 1, (int)remaining_ms);
		if (prc < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (prc == 0)
			return -1;


		if (pfd.revents & (POLLERR | POLLNVAL))
			return -1;

		n = read(fd, buf + total, nbytes - total);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (n == 0)
			return -1;
		total += (size_t)n;
	}
	return 0;
}




static int
recv_path(int fd, char *buf, size_t bufsiz)
{
	uint8_t len_buf[4];
	uint32_t len;

	if (recv_deadline(fd, len_buf, sizeof len_buf, 5) < 0)
		return -1;

	len = get_be32(len_buf);

	if (len == 0 || len >= bufsiz)
		return -1;

	if (recv_deadline(fd, (uint8_t *)buf, len, 5) < 0)
		return -1;

	buf[len] = '\0';
	return 0;
}


static ssize_t
read_file(int fd, void *buf, size_t nbytes, int *eof)
{
	uint8_t *bp = buf;
	ssize_t total = 0;

	if (eof)
		*eof = 0;

	while (nbytes > 0) {
		ssize_t n = read(fd, bp + total, nbytes);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (n == 0) {
			if (eof)
				*eof = 1;
			return total;
		}
		total += n;
		nbytes -= n;
	}
	return total;
}

static void
free_buffers(void)
{
	if (ab.cipher) {
		sodium_memzero(ab.cipher, ab.cipher_sz);
		sodium_munlock(ab.cipher, ab.cipher_sz);
		free(ab.cipher);
		ab.cipher = NULL;
	}
	if (ab.plain) {
		sodium_memzero(ab.plain, ab.plain_sz);
		sodium_munlock(ab.plain, ab.plain_sz);
		free(ab.plain);
		ab.plain = NULL;
	}
}

static int
alloc_buffers(void)
{
	ab.cipher_sz = SAFE_CHUNK_SIZE +
	               crypto_secretstream_xchacha20poly1305_ABYTES;
	ab.plain_sz = SAFE_CHUNK_SIZE;
	ab.cipher = malloc(ab.cipher_sz);
	ab.plain  = malloc(ab.plain_sz);
	if (!ab.cipher || !ab.plain) {
		free_buffers();
		return -1;
	}
	if (sodium_mlock(ab.cipher, ab.cipher_sz) < 0) {
		if (!getenv("SAFE_UNSAFE_MLOCK"))
			goto fail;
		warnx("sodium_mlock(cipher) failed, continuing anyway");
	}
	if (sodium_mlock(ab.plain, ab.plain_sz) < 0) {
		if (!getenv("SAFE_UNSAFE_MLOCK"))
			goto fail;
		warnx("sodium_mlock(plain) failed, continuing anyway");
	}
	return 0;

fail:

	free_buffers();
	return -1;
}

static int
creatsock(char *sockpath)
{
	int sfd;
	struct sockaddr_un addr;
	size_t plen;
	mode_t old_umask;
	struct stat st;
	char dir[PATH_MAX];
	char *slash;

	plen = strlen(sockpath);
	if (plen >= sizeof(addr.sun_path))
		return -1;


	memcpy(dir, sockpath, plen + 1);
	slash = strrchr(dir, '/');
	if (!slash) {
		memcpy(dir, ".", 2);
	} else if (slash == dir) {
		dir[1] = 0;
	} else {
		*slash = 0;
	}
	if (lstat(dir, &st) < 0)
		return -1;
	if (!S_ISDIR(st.st_mode)) {
		errno = EACCES;
		return -1;
	}
	if (st.st_uid != geteuid()) {
		errno = EACCES;
		return -1;
	}
	if (st.st_mode & 027) {   
		errno = EACCES;
		return -1;
	}

	sfd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (sfd < 0)
		return -1;

	if (lstat(sockpath, &st) == 0) {
		if (S_ISSOCK(st.st_mode)) {
			struct sockaddr_un pa;
			int pfd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);

			if (pfd >= 0) {
				memset(&pa, 0, sizeof pa);
				pa.sun_family = AF_UNIX;
				memcpy(pa.sun_path, sockpath, plen + 1);
				if (connect(pfd, (struct sockaddr *)&pa,
				    sizeof pa) == 0) {
					/* somebody is listening */
					close(pfd);
					close(sfd);
					errno = EADDRINUSE;
					return -1;
				}
				close(pfd);
			}
			unlink(sockpath);
		} else {
			close(sfd);
			errno = EEXIST;
			return -1;
		}
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	memcpy(addr.sun_path, sockpath, plen + 1);


	old_umask = umask(socket_relaxed ? 0117 : 0177);
	if (bind(sfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		umask(old_umask);
		close(sfd);
		return -1;
	}
	umask(old_umask);

	if (listen(sfd, 10) < 0) {
		close(sfd);
		return -1;
	}
	return sfd;
}


static int
publish_sock(const char *sockpath)
{
	const char *xdg = getenv("XDG_RUNTIME_DIR");
	char dir[PATH_MAX], path[PATH_MAX], tmp[PATH_MAX];
	struct stat st;
	size_t len;
	int fd;

	if (!xdg || !*xdg)
		return 0;

	if (snprintf(dir, sizeof dir, "%s/safe", xdg) >= (int)sizeof dir)
		return -1;
	if (mkdir(dir, 0700) < 0 && errno != EEXIST)
		return -1;


	if (lstat(dir, &st) < 0)
		return -1;
	if (!S_ISDIR(st.st_mode) || st.st_uid != geteuid() || (st.st_mode & 027))
		return -1;

	if (snprintf(path, sizeof path, "%s/sock", dir) >= (int)sizeof path)
		return -1;
	if (snprintf(tmp, sizeof tmp, "%s/sock.tmp.%d", dir, getpid())
	    >= (int)sizeof tmp)
		return -1;

	fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW,
	    0600);
	if (fd < 0)
		return -1;
	len = strlen(sockpath);
	if (write(fd, sockpath, len) != (ssize_t)len) {
		close(fd);
		unlink(tmp);
		return -1;
	}
	close(fd);
	if (rename(tmp, path) < 0) {
		unlink(tmp);
		return -1;
	}
	return 0;
}


static void
unpublish_sock(const char *sockpath)
{
	const char *xdg = getenv("XDG_RUNTIME_DIR");
	char path[PATH_MAX], buf[PATH_MAX];
	ssize_t n;
	int fd;

	if (!xdg || !*xdg)
		return;

	if (snprintf(path, sizeof path, "%s/safe/sock", xdg)
	    >= (int)sizeof path)
		return;

	fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (fd < 0)
		return;
	n = read(fd, buf, sizeof buf - 1);
	close(fd);
	if (n <= 0)
		return;
	buf[n] = '\0';

	if (strcmp(buf, sockpath) != 0)
		return;		

	unlink(path);

}

static int
write_pidfile(const char *sdir)
{
	char path[PATH_MAX];
	char buf[32];
	int fd, n;

	if (!sdir || !*sdir)
		return -1;
	if (snprintf(path, sizeof path, "%s/agent.pid", sdir)
	    >= (int)sizeof path)
		return -1;

	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC,
	    0640);
	if (fd < 0)
		return -1;
	if (fchmod(fd, 0640) < 0) {
		close(fd);
		return -1;
	}
	n = snprintf(buf, sizeof buf, "%d\n", (int)getpid());
	if (n < 0 || (size_t)n >= sizeof buf) {
		close(fd);
		return -1;
	}
	if (write(fd, buf, (size_t)n) != n) {
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
}

static void
unlink_pidfile(const char *sdir)
{
	char path[PATH_MAX];

	if (!sdir || !*sdir)
		return;
	if (snprintf(path, sizeof path, "%s/agent.pid", sdir)
	    >= (int)sizeof path)
		return;
	unlink(path);
}

static void
forgetkey(void)
{
	sodium_memzero(s.saltkey, sizeof(s.saltkey));
	s.loaded = 0;
	s.one_shot = 0;
	alarm(0);
}

static void
sighandler(int signal)
{
	switch (signal) {
	case SIGINT:
	case SIGTERM:
	case SIGHUP:	
		sig_quit = 1;
		break;
	case SIGALRM:
	case SIGUSR1:
		sig_forget = 1;
		break;
	}
}

static int
peer_allowed_for_pd(uid_t uid)
{
        if (uid == (uid_t)-1)
                return 0;
        if (uid == geteuid())
                return 1;
        if (have_allow_uid && uid == allow_uid)
                return 1;
        return 0;
}

static int
peer_is_owner(uid_t uid)
{

	return uid == geteuid();
}

static int
peer_allowed_for_f(uid_t uid)
{
	return uid == geteuid() || uid == 0;
}


static int
confirm_request(const char *path)
{
	char cmd_copy[PATH_MAX];
	char *argv[16];
	char *tok, *save;
	pid_t pid;
	int argc = 0, status;

	if (confirm_cmd[0] == '\0')
		return 1;
	if (path[0] == '-')
		return 0;


	snprintf(cmd_copy, sizeof cmd_copy, "%s", confirm_cmd);
	save = NULL;
	for (tok = strtok_r(cmd_copy, " \t", &save);
	     tok != NULL && argc < 14;
	     tok = strtok_r(NULL, " \t", &save))
		argv[argc++] = tok;
	if (argc == 0)
		return 0;
	argv[argc++] = (char *)path;
	argv[argc] = NULL;

	pid = fork();
	if (pid < 0) {
		warn("fork for confirm");
		return 0;
	}
	if (pid == 0) {
		sigset_t none;

		sigemptyset(&none);
		sigprocmask(SIG_SETMASK, &none, NULL);
		execvp(argv[0], argv);
		_exit(127);
	}
	for (;;) {
		if (waitpid(pid, &status, 0) >= 0)
			break;
		if (errno != EINTR)
			return 0;
		if (sig_quit || sig_forget)
			return 0;
	}
	return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 1 : 0;
}

/* authenticate path; with cfd >= 0 also stream the plaintext */
static long long
stream_entry(int cfd, const char *path, uint8_t *pt_salt)
{
	uint8_t sshdr[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
	uint8_t salt[SAFE_SALT_SIZE];
	uint8_t hb[SAFE_HEADER_SIZE];
	uint8_t ad[SAFE_AD_MAX];
	crypto_secretstream_xchacha20poly1305_state st;
	const uint8_t *key = s.saltkey + crypto_pwhash_SALTBYTES;
	unsigned long long mlen;
	long long total = 0;
	uint8_t tag, dummy;
	unsigned version;
	size_t adlen, olen;
	int fd, eof = 0, eof2 = 0, final_seen = 0;
	ssize_t n;

#if defined(__linux__) && defined(SYS_openat2)
	{
		struct open_how {
			uint64_t flags;
			uint64_t mode;
			uint64_t resolve;
		} how = {
			.flags = O_RDONLY | O_CLOEXEC,
			.mode = 0,
			/* RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH */
			.resolve = 0x04 | 0x08
		};
		fd = (int)syscall(SYS_openat2, store_dirfd, path, &how,
		    sizeof(how));
	}
#else
	fd = openat(store_dirfd, path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
#endif
	if (fd < 0)
		return -1;

	if (read_file(fd, hb, sizeof hb, NULL) != (ssize_t)sizeof hb ||
	    safe_hdr_parse(hb, salt, &version) < 0 ||
	    safe_ad_build(ad, sizeof ad, hb, version, path, &adlen) < 0)
		goto fail;
	if (pt_salt)
		memcpy(pt_salt, salt, sizeof salt);
	if (read_file(fd, sshdr, sizeof sshdr, NULL) != (ssize_t)sizeof sshdr)
		goto fail;
	if (crypto_secretstream_xchacha20poly1305_init_pull(&st, sshdr, key) != 0)
		goto fail;

	while ((n = read_file(fd, ab.cipher, ab.cipher_sz, &eof)) > 0) {
		if (crypto_secretstream_xchacha20poly1305_pull(&st, ab.plain,
		    &mlen, &tag, ab.cipher, (size_t)n, ad, adlen) != 0)
			goto fail;
		olen = (size_t)mlen;
		if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
			if (version == SAFE_FORMAT &&
			    safe_unpad_final(ab.plain, olen, &olen) < 0)
				goto fail;
			final_seen = 1;
		} else if (tag != 0 ||
		    (version == SAFE_FORMAT && olen != SAFE_CHUNK_SIZE)) {
			goto fail;
		}
		total += (long long)olen;
		if (total > (long long)AG_E_MAX_TOTAL)
			goto fail;
		if (cfd >= 0 && xwrite(cfd, ab.plain, olen) != (ssize_t)olen)
			goto fail;
		if (final_seen)
			break;
		if (eof)
			goto fail;
	}
	if (n < 0 || !final_seen)
		goto fail;
	/* no trailing data after the final chunk */
	if (read_file(fd, &dummy, 1, &eof2) != 0 || !eof2)
		goto fail;
	close(fd);
	sodium_memzero(&st, sizeof st);
	sodium_memzero(ab.plain, ab.plain_sz);
	return total;
fail:
	close(fd);
	sodium_memzero(&st, sizeof st);
	sodium_memzero(ab.plain, ab.plain_sz);
	return -1;
}

/* path checks shared by D, E and L */
static int
check_path(const char *cmd, const char *path, uid_t puid)
{
	if (!valid_secret_path(path)) {
		if (verbose)
			fprintf(stderr, "%s: invalid path\n", cmd);
		return -1;
	}
	if (strcmp(path, master_entry) == 0 && puid != geteuid()) {
		if (verbose)
			fprintf(stderr, "%s: master refused for non-owner\n", cmd);
		return -1;
	}
	if (have_prefix && strncmp(path, prefix, strlen(prefix)) != 0) {
		if (verbose)
			fprintf(stderr, "%s: prefix mismatch: %s\n", cmd, path);
		return -1;
	}
	return 0;
}

/* D: authenticate the whole entry before sending any of it */
static int
handle_D(int cfd, uid_t puid)
{
	char path[PATH_MAX];
	uint8_t hdr[1 + 4];
	long long len;

	if (!s.loaded)
		return -1;
	if (recv_path(cfd, path, sizeof path) < 0)
		return -1;
	if (check_path("D", path, puid) < 0)
		return -1;
	if (!confirm_request(path)) {
		if (verbose)
			fprintf(stderr, "D: user denied: %s\n", path);
		return -1;
	}
	len = stream_entry(-1, path, NULL);
	if (len < 0)
		return -1;
	if (strcmp(path, master_entry) == 0)
		len = 0;
	hdr[0] = AG_OK;
	put_be32(hdr + 1, (uint32_t)len);
	if (xwrite(cfd, hdr, sizeof hdr) != (ssize_t)sizeof hdr)
		return -1;
	if (strcmp(path, master_entry) == 0)
		return 0;
	if (stream_entry(cfd, path, NULL) != len)
		return -1;	/* entry changed under us: client sees a short read */
	return 0;
}

static int
strictly_beneath(const char *dir, const char *pfx)
{
	size_t pl = strlen(pfx);

	if (pl == 0 || strncmp(dir, pfx, pl) != 0)
		return 0;
	if (pfx[pl - 1] == '/')
		return dir[pl] != '\0';
	return dir[pl] == '/' && dir[pl + 1] != '\0';
}

/* L: list the usernames in one directory beneath the prefix */
static int
handle_L(int cfd, uid_t puid)
{
	static char out[AG_L_MAX_BYTES];
	char dir[PATH_MAX], probe[PATH_MAX];
	uint8_t hdr[1 + 4];
	size_t olen = 0;
	int count = 0, fd;
	struct dirent *de;
	DIR *d;

	if (!s.loaded)
		return -1;
	if (recv_path(cfd, dir, sizeof dir) < 0)
		return -1;
	if (snprintf(probe, sizeof probe, "%s/x", dir) >= (int)sizeof probe ||
	    check_path("L", probe, puid) < 0)
		return -1;
	if (have_prefix ? !strictly_beneath(dir, prefix)
	                : !peer_is_owner(puid)) {
		if (verbose)
			fprintf(stderr, "L: refused: %s\n", dir);
		return -1;
	}

#if defined(__linux__) && defined(SYS_openat2)
	{
		struct open_how {
			uint64_t flags;
			uint64_t mode;
			uint64_t resolve;
		} how = {
			.flags = O_RDONLY | O_DIRECTORY | O_CLOEXEC,
			.mode = 0,
			/* RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH */
			.resolve = 0x04 | 0x08
		};
		fd = (int)syscall(SYS_openat2, store_dirfd, dir, &how,
		    sizeof(how));
	}
#else
	fd = openat(store_dirfd, dir,
	    O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
#endif
	if (fd >= 0) {
		if (!(d = fdopendir(fd))) {
			close(fd);
			return -1;
		}
		while ((de = readdir(d)) != NULL && count < AG_L_MAX_NAMES) {
			struct stat sb;
			size_t nl = strlen(de->d_name);

			if (!valid_username(de->d_name))
				continue;	/* also skips "." and ".." */
			if (de->d_type != DT_REG) {
				if (de->d_type != DT_UNKNOWN ||
				    fstatat(dirfd(d), de->d_name, &sb,
				    AT_SYMLINK_NOFOLLOW) < 0 ||
				    !S_ISREG(sb.st_mode))
					continue;
			}
			if (olen + (olen ? 1 : 0) + nl > sizeof out)
				break;
			if (olen)
				out[olen++] = '\n';
			memcpy(out + olen, de->d_name, nl);
			olen += nl;
			count++;
		}
		closedir(d);
	} else if (errno != ENOENT && errno != ENOTDIR) {
		return -1;
	}

	hdr[0] = AG_OK;
	put_be32(hdr + 1, (uint32_t)olen);
	if (xwrite(cfd, hdr, sizeof hdr) != (ssize_t)sizeof hdr ||
	    (olen && xwrite(cfd, out, olen) != (ssize_t)olen))
		return -1;
	return 0;
}

/* I: is the loaded key this store's key? */
static int
handle_I(int cfd)
{
	uint8_t out[1 + 1 + 8 + 8];
	struct stat sb;
	uint8_t st = AG_INFO_NOKEY;

	if (fstat(store_dirfd, &sb) < 0)
		return -1;
	if (s.loaded)
		st = stream_entry(-1, master_entry, NULL) >= 0 ?
		    AG_INFO_OK : AG_INFO_BADKEY;
	out[0] = AG_OK;
	out[1] = st;
	put_be64(out + 2, (uint64_t)sb.st_dev);
	put_be64(out + 10, (uint64_t)sb.st_ino);
	return xwrite(cfd, out, sizeof out) == (ssize_t)sizeof out ? 0 : -1;
}

/* E: encrypt frames of up to 8192 bytes */
static int
handle_E(int cfd, uid_t puid)
{
	char path[PATH_MAX];
	uint8_t hb[1 + SAFE_HEADER_SIZE +
	    crypto_secretstream_xchacha20poly1305_HEADERBYTES];
	uint8_t lenb[4];
	uint8_t ad[SAFE_AD_MAX];
	crypto_secretstream_xchacha20poly1305_state st;
	const uint8_t *key = s.saltkey + crypto_pwhash_SALTBYTES;
	struct timespec t0, t1;
	unsigned long long clen;
	uint64_t total = 0;
	size_t adlen, plen;
	int ok = -1;

	if (!s.loaded || puid != geteuid())
		return -1;
	if (recv_path(cfd, path, sizeof path) < 0)
		return -1;
	if (check_path("E", path, puid) < 0 || strcmp(path, master_entry) == 0)
		return -1;
	if (!confirm_request(path))
		return -1;

	hb[0] = AG_OK;
	safe_hdr_build(hb + 1, s.saltkey);
	if (safe_ad_build(ad, sizeof ad, hb + 1, SAFE_FORMAT, path, &adlen) < 0)
		return -1;
	if (crypto_secretstream_xchacha20poly1305_init_push(&st,
	    hb + 1 + SAFE_HEADER_SIZE, key) != 0)
		return -1;
	if (xwrite(cfd, hb, sizeof hb) != (ssize_t)sizeof hb)
		goto out;

	clock_gettime(CLOCK_MONOTONIC, &t0);
	for (;;) {
		uint32_t n;
		uint8_t tag;
		long left;

		clock_gettime(CLOCK_MONOTONIC, &t1);
		left = AG_E_MAX_SECONDS - (long)(t1.tv_sec - t0.tv_sec);
		if (left <= 0 || recv_deadline(cfd, lenb, 4, (int)left) < 0)
			goto out;
		n = get_be32(lenb);
		if (n > SAFE_CHUNK_SIZE)
			goto out;
		total += n;
		if (total > AG_E_MAX_TOTAL)
			goto out;
		if (n > 0) {
			left = AG_E_MAX_SECONDS - (long)(t1.tv_sec - t0.tv_sec);
			if (left <= 0 ||
			    recv_deadline(cfd, ab.plain, n, (int)left) < 0)
				goto out;
		}
		tag = n < SAFE_CHUNK_SIZE ?
		    crypto_secretstream_xchacha20poly1305_TAG_FINAL : 0;
		plen = n;
		if (tag && safe_pad_final(ab.plain, n, &plen) < 0)
			goto out;
		if (crypto_secretstream_xchacha20poly1305_push(&st, ab.cipher,
		    &clen, ab.plain, plen, ad, adlen, tag) != 0)
			goto out;
		if (xwrite(cfd, ab.cipher, (size_t)clen) != (ssize_t)clen)
			goto out;
		if (tag) {
			ok = 0;
			break;
		}
	}
out:
	sodium_memzero(&st, sizeof st);
	sodium_memzero(ab.plain, ab.plain_sz);
	sodium_memzero(ab.cipher, ab.cipher_sz);
	return ok;
}


static int
servekey(int sfd, int timeout)
{
	uint8_t cmd, flagb = 0;
	static uint8_t tmpkey[sizeof(s.saltkey)];
	sigset_t blk, orig_mask;

	if (verbose)
		fprintf(stderr, "listening on %s (store %s)\n", sockp, store_dir);

	s.loaded = 0;
	s.one_shot = 0;

	if (sodium_mlock(tmpkey, sizeof tmpkey) < 0) {
		if (!getenv("SAFE_UNSAFE_MLOCK"))
			errx(1, "sodium_mlock(tmpkey) failed (set "
			    "SAFE_UNSAFE_MLOCK=1 to ignore)");
		warnx("sodium_mlock(tmpkey) failed, continuing anyway");
	}

	sigemptyset(&blk);
	sigaddset(&blk, SIGINT);
	sigaddset(&blk, SIGTERM);
	sigaddset(&blk, SIGHUP);
	sigaddset(&blk, SIGUSR1);
	sigaddset(&blk, SIGALRM);
	sigprocmask(SIG_BLOCK, &blk, &orig_mask);
	fcntl(sfd, F_SETFL, fcntl(sfd, F_GETFL) | O_NONBLOCK);

	for (;;) {
		int cfd;
		uid_t puid;
		struct peer_info pi;

		if (sig_quit) {
			sodium_memzero(s.saltkey, sizeof(s.saltkey));
			free_buffers();
			unpublish_sock(sockp);
			unlink(sockp);
			unlink_pidfile(sock_dir);
			if (created_dir && sock_dir[0])
				rmdir(sock_dir);
			_exit(0);
		}
		if (sig_forget) {
			forgetkey();
			sig_forget = 0;
		}

		{
			struct pollfd lp = { .fd = sfd, .events = POLLIN };

			if (ppoll(&lp, 1, NULL, &orig_mask) < 0 && errno == EINTR)
				continue;
		}

		cfd = accept4(sfd, NULL, NULL, SOCK_CLOEXEC);
		if (cfd < 0) {
			if (errno == EINTR || errno == EAGAIN ||
			    errno == EWOULDBLOCK)
				continue;
			sodium_memzero(s.saltkey, sizeof(s.saltkey));
			free_buffers();
			unlink(sockp);
			unlink_pidfile(sock_dir);
			err(1, "%s", sockp);
		}


		{
			struct timeval tv = { .tv_sec = 30, .tv_usec = 0 };
			(void)setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO,
			    &tv, sizeof tv);
		}

		pi = peer_cred(cfd);
		puid = pi.uid;

		if (peer_sec_label[0]) {
			char label[256];
			int lsrc = peer_lsm_label(cfd, label, sizeof label);
			if (lsrc < 0 || strcmp(label, peer_sec_label) != 0) {
				if (verbose) {
					if (lsrc < 0)
						fprintf(stderr,
						    "peer LSM label "
						    "unreadable, want %s\n",
						    peer_sec_label);
					else
						fprintf(stderr,
						    "peer LSM label "
						    "mismatch: want %s, "
						    "got %s\n",
						    peer_sec_label, label);
				}
				close(cfd);
				continue;
			}
		}

		if (peer_exe_path[0] &&
		    !peer_matches_exe(pi.pid, peer_exe_path)) {
			if (verbose)
				fprintf(stderr,
				    "peer exe mismatch: %s\n", peer_exe_path);
			close(cfd);
			continue;
		}

		if (recv_deadline(cfd, &cmd, 1, 5) < 0) {
			close(cfd);
			continue;
		}

		switch (cmd) {
		case AG_PUSH:
			if (!peer_is_owner(puid)) {
				if (verbose)
					fprintf(stderr, "P: peer uid %d denied\n",
					    (int)puid);
				break;
			}
			if (recv_deadline(cfd, tmpkey, sizeof(tmpkey), 5) == 0 &&
			    recv_deadline(cfd, &flagb, 1, 5) == 0 && flagb <= 1) {
				memcpy(s.saltkey, tmpkey, sizeof(tmpkey));
				s.loaded = 1;
				s.one_shot = flagb;
				alarm((unsigned)timeout);
				if (verbose)
					fprintf(stderr, "key loaded%s\n",
					    flagb ? " (one-shot)" : "");
				(void)xwrite(cfd, "K", 1);
			} else if (verbose) {
				fprintf(stderr, "short push; keeping current key\n");
			}
			sodium_memzero(tmpkey, sizeof(tmpkey));
			break;

		case AG_INFO:
			if (peer_is_owner(puid))
				(void)handle_I(cfd);
			break;

		case AG_DECRYPT:
			if (!peer_allowed_for_pd(puid))
				break;
			if (handle_D(cfd, puid) == 0 && s.one_shot)
				forgetkey();
			break;

		case AG_LIST:
			if (!peer_allowed_for_pd(puid))
				break;
			(void)handle_L(cfd, puid);
			break;

		case AG_ENCRYPT:
			if (!peer_is_owner(puid))
				break;
			if (handle_E(cfd, puid) == 0 && s.one_shot)
				forgetkey();
			break;

		case AG_FORGET:
			if (!peer_allowed_for_f(puid)) {
				if (verbose)
					fprintf(stderr,
					    "F: peer uid %d denied\n", (int)puid);
				break;
			}
			forgetkey();
			if (verbose)
				fprintf(stderr, "key forgotten on request\n");
			(void)xwrite(cfd, "K", 1);
			break;

		default:
			if (verbose)
				fprintf(stderr, "unknown command %#x\n", cmd);
			break;
		}
		close(cfd);
	}

	close(sfd);
	return -1;
}

int
main(int argc, char *argv[])
{
	pid_t pid;
	int fd = -1, timeout = 0, dflag = 0, sfd = -1;
	int ready[2] = { -1, -1 };
	size_t dirlen;
	char path[PATH_MAX];
	const char *store_arg = NULL;

	pid = getpid();

	ARGBEGIN {
	case 'd':
		dflag = 1;
		break;
	case 'f':
		{

			const char *fp = EARGF(usage());
			size_t plen = strlen(fp);

			if (plen >= sizeof sockpath_buf)
				errx(1, "-f path too long");
			if (fp[0] != '/') {
				char cwd[PATH_MAX];
				if (getcwd(cwd, sizeof cwd) == NULL)
					err(1, "getcwd for -f");
				if (snprintf(sockpath_buf, sizeof sockpath_buf,
				    "%s/%s", cwd, fp)
				    >= (int)sizeof sockpath_buf)
					errx(1, "-f path too long after "
					        "CWD prefix");
			} else {
				memcpy(sockpath_buf, fp, plen + 1);
			}
			sockp = sockpath_buf;
		}
		break;
	case 'p':
		{
			const char *p = EARGF(usage());
			size_t plen = strlen(p);
			if (plen >= sizeof prefix)
				errx(1, "-p prefix too long");
			if (plen == 0 || p[plen - 1] != '/')
				errx(1, "-p prefix must be non-empty and end with '/'");
			memcpy(prefix, p, plen + 1);
			have_prefix = 1;
		}
		break;
	case 'g':
		socket_relaxed = 1;
		break;
	case 's':
		store_arg = EARGF(usage());
		break;
	case 'e':
		{
			const char *ep = EARGF(usage());
			size_t elen = strlen(ep);
			if (elen >= sizeof peer_exe_path)
				errx(1, "-e path too long");
			memcpy(peer_exe_path, ep, elen + 1);
		}
		break;
	case 'S':
		{
			const char *sp = EARGF(usage());
			size_t slen = strlen(sp);
			if (slen >= sizeof peer_sec_label)
				errx(1, "-S label too long");
			memcpy(peer_sec_label, sp, slen + 1);
		}
		break;
	case 'c':
		{
			const char *cp = EARGF(usage());
			size_t clen = strlen(cp);
			if (clen >= sizeof confirm_cmd)
				errx(1, "-c command too long");
			memcpy(confirm_cmd, cp, clen + 1);
		}
		break;
	case 't':
		{

			const char *tp = EARGF(usage());
			char *end;
			long v;

			errno = 0;
			v = strtol(tp, &end, 10);
			if (errno != 0 || end == tp || *end != '\0' ||
			    v < 0 || v > INT_MAX)
				errx(1, "invalid timeout: %s", tp);
			timeout = (int)v;
		}
		break;
        case 'u':
                {
                        char *end;
                        long v;
                        errno = 0;
                        const char *up = EARGF(usage());
                        v = strtol(up, &end, 10);
                        if (errno != 0 || end == up || *end != '\0' || v < 0 ||
                            (unsigned long)v > (unsigned long)(uid_t)-1 ||
                            (uid_t)v == (uid_t)-1)
                                errx(1, "invalid uid");
                        allow_uid = (uid_t)v;
                        have_allow_uid = 1;
                }
                break;
	case 'v':
		verbose = 1;
		break;
	default:
		usage();
	} ARGEND


	if (socket_relaxed && !have_prefix)
		warnx("-g has no prefix restriction; only use it with -p");

	if (timeout == 0) {
		if (!getenv("SAFE_UNSAFE_TIMEOUT"))
			errx(1, "key timeout required; pass a nonzero -t <seconds> "
			    "or set SAFE_UNSAFE_TIMEOUT=1");
		warnx("timeout 0: the key is never forgotten automatically");
	}


#ifndef __linux__
	if (peer_exe_path[0])
		errx(1, "-e is Linux-only (requires /proc/<pid>/exe)");
#endif

#ifdef SANDBOX

	if (peer_exe_path[0])
		errx(1, "-e is not supported in this build: seccomp "
		        "forbids readlink(2); use a non-SANDBOX build "
		        "or drop -e");
	if (confirm_cmd[0])
		errx(1, "-c is not supported in this build: seccomp "
		        "forbids clone(2)/wait4(2)/execve(2); use a "
		        "non-SANDBOX build or drop -c");
#elif defined(__linux__)

	if (peer_exe_path[0]) {
		char tbuf[PATH_MAX];
		if (readlink("/proc/1/exe", tbuf, sizeof tbuf - 1) < 0)
			warnx("-e set but cross-uid /proc readlink denied; "
			      "peer exe check will reject all requests "
			      "unless agent and peer share a uid");
	}
#endif


	if (peer_sec_label[0]) {
#ifndef SO_PEERSEC
		warnx("-S requires SO_PEERSEC (Linux with LSM); "
		      "every peer will be rejected");
#else
		if (verbose)
			fprintf(stderr, "expecting peer LSM label: %s\n",
			    peer_sec_label);
#endif
	}

	if (sockp) {
		size_t plen = strlen(sockp);
		if (plen >= sizeof(path))
			errx(1, "socket path too long");
		memcpy(path, sockp, plen + 1);
	} else {
		memcpy(path, agent_socktmp, sizeof(agent_socktmp));
		if (!mkdtemp(path))
			err(1, "mkdtemp: %s", path);
		created_dir = 1;
		dirlen = strnlen(path, sizeof(path));
		snprintf(path + dirlen, PATH_MAX - dirlen, agent_sockfmt, pid);
		sockp = path;
	}

	{
		size_t plen = strlen(sockp);
		char *slash;
		memcpy(sock_dir, sockp, plen + 1);
		slash = strrchr(sock_dir, '/');
		if (slash)
			*slash = 0;
		else
			sock_dir[0] = 0;
	}


	{
		const char *dir = store_arg;
		if (!dir)
			dir = getenv("SAFE_DIR");
		if (!dir)
			dir = safe_dir;

		if (!realpath(dir, store_dir))
			err(1, "realpath store: %s", dir);
		store_dirfd = open(store_dir,
		    O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
		if (store_dirfd < 0)
			err(1, "open store: %s", store_dir);
		{
			struct stat sst;

			if (fstat(store_dirfd, &sst) < 0)
				err(1, "fstat store: %s", store_dir);
			if (sst.st_uid != geteuid())
				errx(1, "%s is not owned by the agent user", store_dir);
			if (sst.st_mode & 022)
				errx(1, "%s is group- or world-writable", store_dir);
		}
	}



#ifdef _DEBUG
	warnx("WARNING: _DEBUG build - seccomp/Landlock/core-dumps disabled");
#endif

#ifdef SANDBOX
	if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) < 0)
		warn("prctl PR_SET_DUMPABLE");
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
		warn("prctl PR_SET_NO_NEW_PRIVS");
#endif

#ifndef _DEBUG
	{
		struct rlimit rlim;
		rlim.rlim_cur = rlim.rlim_max = 0;
		if (setrlimit(RLIMIT_CORE, &rlim) < 0)
			err(1, "setrlimit RLIMIT_CORE");
	}
#endif

#ifdef __OpenBSD__
	if (unveil(_PATH_DEVNULL, "rw") == -1)
		err(1, "unveil %s", _PATH_DEVNULL);
	if (unveil(sockp, "c") == -1)
		err(1, "unveil %s", sockp);
	if (unveil(store_dir, "r") == -1)
		err(1, "unveil %s", store_dir);
	if (created_dir) {
		char *d = dirname(sockp);
		if (unveil(d, "c") == -1)
			err(1, "unveil %s", d);
	}
	if (pledge("stdio unix proc cpath rpath", NULL) == -1)
		err(1, "pledge");
#endif

	signal(SIGPIPE, SIG_IGN);

	if (!dflag) {
		if (pipe(ready) < 0)
			err(1, "pipe");
		fcntl(ready[0], F_SETFD, FD_CLOEXEC);
		fcntl(ready[1], F_SETFD, FD_CLOEXEC);

		if (verbose)
			fprintf(stderr, "forking agent to the background\n");

		pid = fork();
		if (pid < 0)
			err(1, "fork");

		if (pid) {
			char c;
			ssize_t r;
			close(ready[1]);
			r = read(ready[0], &c, 1);
			close(ready[0]);
			if (r != 1 || c != 'R') {
				waitpid(pid, NULL, 0);
				return 1;
			}
			if (verbose)
				fprintf(stderr, "agent pid is %d\n", pid);
			printf("SAFE_PID=%d; export SAFE_PID\n", pid);
			printf("SAFE_SOCK=%s; export SAFE_SOCK\n", sockp);
			return 0;
		}
		close(ready[0]);

		if (setsid() < 0)
			err(1, "setsid");

		if ((fd = open(_PATH_DEVNULL, O_RDWR | O_CLOEXEC, 0)) != -1) {
			(void)dup2(fd, STDIN_FILENO);
			(void)dup2(fd, STDOUT_FILENO);
			if (!verbose)
				(void)dup2(fd, STDERR_FILENO);
			if (fd > 2)
				close(fd);
		}
	} else {
		printf("SAFE_PID=%d; export SAFE_PID\n", getpid());
		printf("SAFE_SOCK=%s; export SAFE_SOCK\n", sockp);
		fflush(stdout);
	}

	{
		struct sigaction sa;
		memset(&sa, 0, sizeof(sa));
		sa.sa_handler = sighandler;
		sigemptyset(&sa.sa_mask);
		sa.sa_flags = 0;
		sigaction(SIGINT, &sa, NULL);
		sigaction(SIGTERM, &sa, NULL);
		sigaction(SIGHUP, &sa, NULL);
		sigaction(SIGUSR1, &sa, NULL);
		sigaction(SIGALRM, &sa, NULL);
	}

	if (sodium_init() < 0) {
		if (!dflag) {
			ssize_t w = write(ready[1], "E", 1);
			(void)w;
		}
		errx(1, "sodium_init");
	}


	if (sodium_mlock(&s, sizeof(s)) < 0) {
		if (!getenv("SAFE_UNSAFE_MLOCK")) {
			if (!dflag) {
				ssize_t w = write(ready[1], "E", 1);
				(void)w;
			}
			errx(1, "sodium_mlock failed (set "
			        "SAFE_UNSAFE_MLOCK=1 to ignore)");
		}
		warnx("sodium_mlock failed, continuing anyway");
	}

	if (alloc_buffers() < 0) {
		if (!dflag) {
			ssize_t w = write(ready[1], "E", 1);
			(void)w;
		}
		errx(1, "alloc buffers (set SAFE_UNSAFE_MLOCK=1 to ignore)");
	}

#ifdef SANDBOX
	if (install_landlock(sock_dir, store_dir, created_dir) < 0) {
		if (!dflag) {
			ssize_t w = write(ready[1], "E", 1);
			(void)w;
		}
		err(1, "landlock");
	}

	if (install_seccomp() < 0) {
		if (!dflag) {
			ssize_t w = write(ready[1], "E", 1);
			(void)w;
		}
		err(1, "seccomp");
	}
#endif

	sfd = creatsock(sockp);
	if (sfd < 0) {
		if (!dflag) {
			ssize_t w = write(ready[1], "E", 1);
			(void)w;
			close(ready[1]);
		}
		err(1, "%s", sockp);
	}


	if (write_pidfile(sock_dir) < 0)
		warn("write_pidfile(%s/agent.pid)", sock_dir);


	if (publish_sock(sockp) < 0)
		warn("publish_sock(%s)", sockp);

	if (!dflag) {
		if (write(ready[1], "R", 1) != 1) {
			close(ready[1]);
			_exit(1);
		}
		close(ready[1]);
	}

	if (verbose)
		fprintf(stderr, "locking key in memory\n");

	(void)servekey(sfd, timeout);
	free_buffers();
	return 0;
}
