#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <netinet/in.h>
#include <signal.h>
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
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef __linux__
# include <sys/syscall.h>
#endif

#include <sodium.h>

#include "arg.h"
#include "readpassphrase.h"
#include "config.h"
#include "proto.h"


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
#endif

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
	uint8_t  raw[SAFE_HEADER_SIZE];	/* as read or written; part of the AD */
};

static struct crypto crypto_defaults = {
	.magic = {'C','R','E','A','M','\1'},
	.version = SAFE_FORMAT,
	.xchacha20poly1305_bufsiz = SAFE_CHUNK_SIZE,
	.argon2id_memory          = crypto_pwhash_argon2id_MEMLIMIT_MODERATE / 1024,
	.argon2id_time            = crypto_pwhash_argon2id_OPSLIMIT_MODERATE,
	.argon2id_threads         = 1,
};

struct safe {
	uint8_t key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
	struct crypto crypto;
	struct safe_buffer cipher;
	struct safe_buffer message;
};

char *argv0;

static void
usage(void)
{
	fprintf(stderr,
	    "usage: %s [-bhkro] [-s safe] [-p prompt] [[-af] entry]\n"
	    "       %s -F\n", argv0, argv0);
	exit(1);
}



#ifdef SANDBOX

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
install_landlock(const char *safe_abs, const char *tty, const char *askpass)
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
	/* what the store is used for: no exec, symlinks or devices */
	const uint64_t store_access =
	    LANDLOCK_ACCESS_FS_READ_FILE   | LANDLOCK_ACCESS_FS_WRITE_FILE |
	    LANDLOCK_ACCESS_FS_READ_DIR    | LANDLOCK_ACCESS_FS_MAKE_REG   |
	    LANDLOCK_ACCESS_FS_MAKE_DIR    | LANDLOCK_ACCESS_FS_REMOVE_FILE;
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

	if (landlock_add_path(ruleset, safe_abs, store_access) < 0) {
		close(ruleset);
		return -1;
	}
	if (tty)
		landlock_add_path(ruleset, tty,
		    LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_WRITE_FILE);
	landlock_add_path(ruleset, "/dev/urandom", LANDLOCK_ACCESS_FS_READ_FILE);
	landlock_add_path(ruleset, "/dev/null",
	    LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_WRITE_FILE);
	if (askpass)
		landlock_add_path(ruleset, askpass,
		    LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_EXECUTE);

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
		close(ruleset);
		return -1;
	}
	rc = syscall(SYS_landlock_restrict_self, ruleset, 0);
	close(ruleset);
	return rc < 0 ? -1 : 0;
}

static int
install_seccomp(int phase)
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
	AS(readlinkat);
#ifdef __NR_mkdir
	AS(mkdir);
#endif
	AS(mkdirat);
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
#ifdef __NR_link
	AS(link);
#endif
#ifdef __NR_linkat
	AS(linkat);
#endif
	AS(fsync); AS(fdatasync);
	AS(chdir); AS(fchdir); AS(getcwd);
	AS(getdents64);
#ifdef __NR_access
	AS(access);
#endif
	AS(faccessat);
#ifdef __NR_faccessat2
	AS(faccessat2);
#endif
	/* termios ioctls for readpassphrase, prompt phase only */
	if (phase == 1) {
		JEQ(__NR_ioctl, 0, 11);
		LD(offsetof(struct seccomp_data, args[1]));
		JEQ(0x5401, 8, 0);	/* TCGETS */
		JEQ(0x5402, 7, 0);	/* TCSETS */
		JEQ(0x5403, 6, 0);	/* TCSETSW */
		JEQ(0x5404, 5, 0);	/* TCSETSF */
		JEQ(0x802c542a, 4, 0);	/* TCGETS2, glibc >= 2.42 */
		JEQ(0x402c542b, 3, 0);	/* TCSETS2 */
		JEQ(0x402c542c, 2, 0);	/* TCSETSW2 */
		JEQ(0x402c542d, 1, 0);	/* TCSETSF2 */
		RET(SECCOMP_RET_KILL_PROCESS);
		RET(SECCOMP_RET_ALLOW);
	}
	AS(fcntl);

	AS(mmap); AS(munmap); AS(mprotect); AS(mremap); AS(madvise);
	AS(brk); AS(mlock); AS(munlock);

	AS(rt_sigaction); AS(rt_sigprocmask); AS(rt_sigreturn);
	AS(sigaltstack); AS(tgkill);
	if (phase == 1)
		AS(kill);
#ifdef __NR_poll
	AS(poll);
#endif
	AS(ppoll);

	AS(getpid); AS(getppid); AS(gettid);
	AS(getuid); AS(geteuid); AS(getgid); AS(getegid); AS(getgroups);
	AS(uname);

	AS(set_tid_address); AS(set_robust_list); AS(rseq);
        AS(prlimit64); AS(getrlimit);
	/* no setrlimit: libc uses prlimit64 */
	AS(clock_gettime); AS(clock_nanosleep); AS(nanosleep);
	AS(getrandom); AS(membarrier); AS(futex); AS(sched_yield);

	AS(connect); AS(sendto); AS(recvfrom);
	AS(sendmsg); AS(recvmsg); AS(shutdown);
	AS(getsockname); AS(getpeername);
	AS(setsockopt); AS(getsockopt);

#ifdef __NR_pipe
	AS(pipe);
#endif
	AS(dup);
#ifdef __NR_dup2
	AS(dup2);
#endif
	AS(dup3);

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

	A(SYS_landlock_create_ruleset);
	A(SYS_landlock_add_rule);
	A(SYS_landlock_restrict_self);

	AS(exit); AS(exit_group);

#ifdef __NR_arch_prctl
	AS(arch_prctl);
#endif

	if (phase == 1) {
#ifdef __NR_fork
		AS(fork);
#endif
#ifdef __NR_vfork
		AS(vfork);
#endif
#ifdef __NR_clone3
		AS(clone3);
#endif
		AS(clone); AS(execve); AS(execveat);
		AS(wait4); AS(waitid);
	}

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

static int
mkdir_p(char *path, mode_t mode)
{
	char tmp[PATH_MAX] = "";
	char *p = NULL;
	size_t len;

	if (!path || !*path)
		return 0;
	snprintf(tmp, sizeof(tmp), "%s", path);
	len = strlen(tmp);
	if (len && tmp[len - 1] == '/')
		tmp[len - 1] = 0;
	if (!tmp[0])
		return 0;
	for (p = tmp + 1; *p; p++)
		if (*p == '/') {
			*p = 0;
			mkdir(tmp, mode);
			*p = '/';
		}
	return mkdir(tmp, mode);
}

static ssize_t
xread(int fd, void *buf, size_t nbytes, int *eof)
{
	uint8_t *bp = buf;
	ssize_t total = 0;

	if (eof) *eof = 0;
	while (nbytes > 0) {
		ssize_t n = read(fd, &bp[total], nbytes);
		if (n < 0) {
			if (errno == EINTR)
				continue;
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

static ssize_t
xwrite(int fd, const void *buf, size_t nbytes)
{
	const uint8_t *bp = buf;
	ssize_t total = 0;

	while (nbytes > 0) {
		ssize_t n = write(fd, &bp[total], nbytes);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			err(1, "write");
		} else if (n == 0)
			return total;
		total += n;
		nbytes -= n;
	}
	return total;
}





static int
sock_send(int fd, const void *buf, size_t nbytes)
{
	const uint8_t *bp = buf;

	while (nbytes > 0) {
		ssize_t n = write(fd, bp, nbytes);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (n == 0)
			return -1;
		bp += n;
		nbytes -= (size_t)n;
	}
	return 0;
}

static int
sock_recv(int fd, void *buf, size_t nbytes)
{
	uint8_t *bp = buf;

	while (nbytes > 0) {
		ssize_t n = read(fd, bp, nbytes);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (n == 0)
			return -1;
		bp += n;
		nbytes -= (size_t)n;
	}
	return 0;
}

static void
safe_alloc(struct safe_buffer *b, ssize_t nbytes)
{
        b->sz = nbytes;
        if (nbytes <= 0) {
                b->buf = NULL;
                b->sz = 0;
                return;
        }
        b->buf = malloc((size_t)nbytes);
        if (!b->buf)
                err(1, "malloc");
	if (sodium_mlock(b->buf, (size_t)nbytes) < 0) {
		if (!getenv("SAFE_UNSAFE_MLOCK"))
			errx(1, "sodium_mlock buffer (set SAFE_UNSAFE_MLOCK=1 to ignore)");
		warnx("sodium_mlock buffer failed, continuing anyway");
	}
}

static void
safe_release(struct safe_buffer *b)
{
	if (!b || !b->buf)
		return;
	sodium_memzero(b->buf, (size_t)b->sz);
	(void)sodium_munlock(b->buf, (size_t)b->sz);
	free(b->buf);
	b->buf = NULL;
	b->sz = 0;
}



static char *
spawn_askpass(const char *askpass, const char *msg, char *buf, size_t bufsiz)
{
	pid_t pid, ret;
	int p[2], eof, status;
	ssize_t n;

	if (!askpass) {
		sodium_memzero(buf, bufsiz);
		return NULL;
	}

	if (pipe(p) < 0)
		return NULL;
	fcntl(p[0], F_SETFD, FD_CLOEXEC);
	fcntl(p[1], F_SETFD, FD_CLOEXEC);

	pid = fork();
	if (pid < 0) {
		close(p[0]);
		close(p[1]);
		return NULL;
	}

	if (!pid) {
		close(p[0]);
		if (dup2(p[1], STDOUT_FILENO) < 0)
			_exit(1);
		close(p[1]);
		execlp(askpass, askpass, msg, NULL);
		_exit(1);
	}
	close(p[1]);

	memset(buf, 0, bufsiz);
	n = xread(p[0], buf, bufsiz - 1, &eof);
	close(p[0]);
	if (n > 0)
		buf[n] = '\0';

	ret = waitpid(pid, &status, 0);

	if (ret < 0 || !WIFEXITED(status) || WEXITSTATUS(status)) {
		sodium_memzero(buf, bufsiz);
		return NULL;
	}

	buf[strcspn(buf, "\r\n")] = '\0';
	return buf;
}

static int
readpass(const char *prompt, char *buf, size_t bufsiz, int askflag, int stdinflag)
{
	char *askpass;


	if (stdinflag) {
		if (!readpassphrase(prompt, buf, bufsiz, RPP_STDIN))
			err(1, "readpassphrase:");
	} else if (askflag) {
		askpass = askpass_path;
		if (getenv("SAFE_ASKPASS"))
			askpass = getenv("SAFE_ASKPASS");
		if (!spawn_askpass(askpass, prompt, buf, bufsiz))
			errx(1, "askpass failed");
	} else {
		if (!readpassphrase(prompt, buf, bufsiz,
		        RPP_ECHO_OFF | RPP_REQUIRE_TTY))
			err(1, "readpassphrase:");
	}

	if (buf[0] == '\0') {
		warnx("empty passphrase");
		return -1;
	}
	if (strnlen(buf, bufsiz) >= bufsiz - 1) {
		sodium_memzero(buf, bufsiz);
		warnx("passphrase too long (limit %zu bytes)", bufsiz - 2);
		return -1;
	}
	return (int)strnlen(buf, bufsiz);
}

static int
deriv(char *pw, struct safe *s)
{
	if (crypto_pwhash(s->key, sizeof(s->key), pw, strlen(pw),
			s->crypto.salt, s->crypto.argon2id_time,
			s->crypto.argon2id_memory * 1024,
			crypto_pwhash_ALG_ARGON2ID13) != 0)
		return -1;
	return 0;
}



#if defined(__linux__) && defined(SYS_renameat2)
# ifndef RENAME_NOREPLACE
#  define RENAME_NOREPLACE 1u
# endif
#endif

static int
rename_noreplace(const char *from, const char *to)
{
#if defined(__linux__) && defined(SYS_renameat2)
	if (syscall(SYS_renameat2, AT_FDCWD, from, AT_FDCWD, to,
	    RENAME_NOREPLACE) == 0)
		return 0;
	if (errno != EINVAL && errno != ENOSYS)
		return -1;
#endif
	if (link(from, to) < 0)
		return -1;
	if (unlink(from) < 0) {
		int saved = errno;
		unlink(to);
		errno = saved;
		return -1;
	}
	return 0;
}

/* authenticate an entry; with out >= 0 also write the plaintext */
static int
pull_entry(struct safe *s, int in, int out, const char *name)
{
	int eof = 0, final_seen = 0, rc = -1;
	ssize_t n;
	uint8_t tag, dummy;
	uint8_t h[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
	uint8_t ad[SAFE_AD_MAX];
	size_t adlen, olen;
	crypto_secretstream_xchacha20poly1305_state st;
	unsigned long long mlen;
	int v12 = s->crypto.version == SAFE_FORMAT;

	if (safe_ad_build(ad, sizeof ad, s->crypto.raw, s->crypto.version,
	    name, &adlen) < 0)
		return -1;
	if (xread(in, h, sizeof(h), NULL) != sizeof(h))
		return -1;
	if (crypto_secretstream_xchacha20poly1305_init_pull(&st, h, s->key))
		return -1;

	while ((n = xread(in, s->cipher.buf, (size_t)s->cipher.sz, &eof)) > 0) {
		if (crypto_secretstream_xchacha20poly1305_pull(&st,
		    s->message.buf, &mlen, &tag, s->cipher.buf, (size_t)n,
		    ad, adlen))
			goto done;
		olen = (size_t)mlen;
		if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
			if (v12 && safe_unpad_final(s->message.buf, olen, &olen) < 0)
				goto done;
			final_seen = 1;
		} else if (tag != 0 || (v12 && olen != SAFE_CHUNK_SIZE)) {
			goto done;	/* writers produce only full plain chunks */
		}
		if (out >= 0 && xwrite(out, s->message.buf, olen) != (ssize_t)olen)
			goto done;
		if (final_seen || eof)
			break;
	}
	if (n < 0 || !final_seen)
		goto done;
	{
		int eof2 = 0;
		if (xread(in, &dummy, 1, &eof2) != 0 || !eof2)
			goto done;
	}
	rc = 0;
done:
	sodium_memzero(&st, sizeof st);
	sodium_memzero(s->message.buf, (size_t)s->message.sz);
	return rc;
}

static int
trydecrypt(struct safe *s, int fd, const char *name)
{
	return pull_entry(s, fd, -1, name);
}

static int
parse_header(const uint8_t *buf, struct crypto *hdr)
{
	uint16_t s;
	uint32_t l;

	memcpy(hdr->magic, buf + 0, 6);
	memcpy(&s, buf + 6, 2);  hdr->version = ntohs(s);
	memcpy(&l, buf + 8, 4);  hdr->xchacha20poly1305_bufsiz = ntohl(l);
	memcpy(&l, buf + 12, 4); hdr->argon2id_memory = ntohl(l);
	memcpy(&l, buf + 16, 4); hdr->argon2id_time = ntohl(l);
	memcpy(&l, buf + 20, 4); hdr->argon2id_threads = ntohl(l);
	memcpy(hdr->salt, buf + 24, 16);
	memcpy(hdr->raw, buf, SAFE_HEADER_SIZE);

	if (memcmp(hdr->magic, crypto_defaults.magic, 6) != 0)
		return -1;
	if (hdr->version != SAFE_FORMAT && hdr->version != SAFE_FORMAT_V11)
		return -1;
	if (hdr->xchacha20poly1305_bufsiz != crypto_defaults.xchacha20poly1305_bufsiz)
		return -1;
	if (hdr->argon2id_memory != crypto_defaults.argon2id_memory)
		return -1;
	if (hdr->argon2id_time   != crypto_defaults.argon2id_time)
		return -1;
	if (hdr->argon2id_threads != crypto_defaults.argon2id_threads)
		return -1;
	return 0;
}

static int
readheader(int fd, struct crypto *hdr)
{
	uint8_t buf[SAFE_HEADER_SIZE];
	if (xread(fd, buf, sizeof(buf), NULL) != sizeof(buf))
		return -1;
	return parse_header(buf, hdr);
}

/* write a 0x12 entry from m/mlen, or from in if m is NULL */
static int
push_entry(struct safe *s, const uint8_t *hdr, const char *m, size_t mlen,
    int in, int out, const char *name)
{
	uint8_t h[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
	uint8_t ad[SAFE_AD_MAX];
	size_t adlen, plen;
	crypto_secretstream_xchacha20poly1305_state st;
	unsigned long long clen;
	int eof = 0, rc = -1;
	ssize_t n;

	if (safe_ad_build(ad, sizeof ad, hdr, SAFE_FORMAT, name, &adlen) < 0)
		return -1;
	if (m && mlen >= SAFE_CHUNK_SIZE)
		return -1;	/* only used for the short master payload */
	if (crypto_secretstream_xchacha20poly1305_init_push(&st, h, s->key))
		return -1;
	if (xwrite(out, h, sizeof(h)) != sizeof(h))
		goto done;

	for (;;) {
		if (m) {
			memcpy(s->message.buf, m, mlen);
			n = (ssize_t)mlen;
		} else {
			n = xread(in, s->message.buf, SAFE_CHUNK_SIZE, &eof);
			if (n < 0)
				goto done;
		}
		if (!m && n == SAFE_CHUNK_SIZE) {
			if (crypto_secretstream_xchacha20poly1305_push(&st,
			    s->cipher.buf, &clen, s->message.buf, SAFE_CHUNK_SIZE,
			    ad, adlen, 0))
				goto done;
			if (xwrite(out, s->cipher.buf, clen) != (ssize_t)clen)
				goto done;
			continue;
		}
		if (safe_pad_final(s->message.buf, (size_t)n, &plen) < 0)
			goto done;
		if (crypto_secretstream_xchacha20poly1305_push(&st,
		    s->cipher.buf, &clen, s->message.buf, plen, ad, adlen,
		    crypto_secretstream_xchacha20poly1305_TAG_FINAL))
			goto done;
		if (xwrite(out, s->cipher.buf, clen) != (ssize_t)clen)
			goto done;
		break;
	}
	rc = 0;
done:
	sodium_memzero(&st, sizeof st);
	sodium_memzero(s->message.buf, (size_t)s->message.sz);
	return rc;
}

static int
readsecret(struct safe *s, int in, int out, const char *name)
{
	return pull_entry(s, in, out, name);
}

static char pending_tmp[PATH_MAX];

static void
rm_pending_tmp(void)
{
	if (pending_tmp[0])
		unlink(pending_tmp);
}

static void
on_term_signal(int sig)
{
	rm_pending_tmp();
	_exit(128 + sig);
}

static int agent_encrypt(const char *, const char *, int, int, struct safe *);

static int
write_atomic_common(struct safe *s, const char *path, const char *name,
                    int in, const char *pass, size_t passlen, int force,
                    const char *agent)
{
	char tmp[PATH_MAX];
	char dir[PATH_MAX];
	char *slash;
	uint8_t hdr[SAFE_HEADER_SIZE];
	sigset_t blk, old;
	int fd, dfd, rc;

	if (snprintf(tmp, sizeof tmp, "%s.XXXXXX", path) >= (int)sizeof tmp)
		return -1;

	/* read by the signal handlers */
	sigemptyset(&blk);
	sigaddset(&blk, SIGINT);
	sigaddset(&blk, SIGTERM);
	sigaddset(&blk, SIGHUP);
	sigprocmask(SIG_BLOCK, &blk, &old);
	fd = mkstemp(tmp);
	if (fd >= 0)
		snprintf(pending_tmp, sizeof pending_tmp, "%s", tmp);
	sigprocmask(SIG_SETMASK, &old, NULL);
	if (fd < 0)
		return -1;
	fcntl(fd, F_SETFD, FD_CLOEXEC);

	if (agent) {
		/* the agent returns the complete file image */
		rc = agent_encrypt(agent, name, in, fd, s);
	} else {
		safe_hdr_build(hdr, s->crypto.salt);
		rc = xwrite(fd, hdr, sizeof hdr) == (ssize_t)sizeof hdr ? 0 : -1;
		if (rc == 0)
			rc = push_entry(s, hdr, pass, passlen, in, fd, name);
		if (rc == 0 && pass) {
			memcpy(s->crypto.raw, hdr, sizeof hdr);
			s->crypto.version = SAFE_FORMAT;
		}
	}
	if (rc < 0 || fsync(fd) < 0) {
		int saved = errno;

		close(fd);
		unlink(tmp);
		pending_tmp[0] = '\0';
		errno = saved;
		return -1;
	}
	close(fd);

	if (force) {
		if (rename(tmp, path) < 0) {
			int saved = errno;

			unlink(tmp);
			pending_tmp[0] = '\0';
			errno = saved;
			return -1;
		}
	} else {
		if (rename_noreplace(tmp, path) < 0) {
			int saved = errno;

			unlink(tmp);
			pending_tmp[0] = '\0';
			errno = saved;
			return -1;
		}
	}

	pending_tmp[0] = '\0';
	if (snprintf(dir, sizeof dir, "%s", path) >= (int)sizeof dir)
		return 0;
	slash = strrchr(dir, '/');
	if (slash)
		*slash = '\0';
	else
		snprintf(dir, sizeof dir, ".");

	dfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (dfd >= 0) {
		fsync(dfd);
		close(dfd);
	}
	return 0;
}

static int
write_secret_atomic(struct safe *s, const char *path, const char *name,
                    int in, int force, const char *agent)
{
	return write_atomic_common(s, path, name, in, NULL, 0, force, agent);
}

static int
write_master_atomic(struct safe *s, const char *path, const char *name,
                    const char *pass, size_t passlen)
{
	return write_atomic_common(s, path, name, -1, pass, passlen, 0, NULL);
}

static int
validate_sock_path(const char *path)
{
	struct stat st;
	char dir[PATH_MAX];
	char *slash;
	size_t plen;

	plen = strlen(path);
	if (plen == 0 || plen >= sizeof(dir))
		return -1;
	memcpy(dir, path, plen + 1);

	slash = strrchr(dir, '/');
	if (!slash) {
		memcpy(dir, ".", 2);
	} else if (slash == dir) {
		dir[1] = 0;
	} else {
		*slash = 0;
	}

	if (lstat(path, &st) < 0)
		return -1;
	if (!S_ISSOCK(st.st_mode))
		return -1;
	if (st.st_uid != geteuid())
		return -1;

	if (lstat(dir, &st) < 0)
		return -1;
	if (!S_ISDIR(st.st_mode))
		return -1;
	if (st.st_mode & 027)   
		return -1;
	if (st.st_uid != geteuid())
		return -1;

	return 0;
}

static int
sockaddr_set(struct sockaddr_un *addr, const char *path)
{
	size_t plen = strlen(path);
	if (plen >= sizeof(addr->sun_path))
		return -1;
	memset(addr, 0, sizeof(*addr));
	addr->sun_family = AF_UNIX;
	memcpy(addr->sun_path, path, plen + 1);
	return 0;
}


static int
agent_connect(const char *path)
{
	struct sockaddr_un addr;
	struct timeval tv = { .tv_sec = 30, .tv_usec = 0 };
	int sfd;

	if (validate_sock_path(path) < 0 || sockaddr_set(&addr, path) < 0)
		return -1;
	sfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sfd < 0)
		return -1;
	fcntl(sfd, F_SETFD, FD_CLOEXEC);
	(void)setsockopt(sfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
	(void)setsockopt(sfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
	if (connect(sfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		close(sfd);
		return -1;
	}
	return sfd;
}

/* push the key to a running agent */
static int
pushkey(struct safe *s, char *path, int once)
{
	uint8_t msg[1 + AG_KEYBLOB + 1], ack = 0;
	int sfd, rc;

	sfd = agent_connect(path);
	if (sfd < 0)
		return -1;
	msg[0] = AG_PUSH;
	memcpy(msg + 1, s->crypto.salt, sizeof(s->crypto.salt));
	memcpy(msg + 1 + sizeof(s->crypto.salt), s->key, sizeof(s->key));
	msg[1 + AG_KEYBLOB] = once ? 1 : 0;
	rc = sock_send(sfd, msg, sizeof msg);
	sodium_memzero(msg, sizeof msg);
	if (rc == 0)
		rc = sock_recv(sfd, &ack, 1) < 0 || ack != AG_OK ? -1 : 0;
	close(sfd);
	return rc;
}

/* does the agent hold this store's key? */
static int
agent_usable(const char *path, dev_t dev, ino_t ino)
{
	uint8_t out[1 + 1 + 8 + 8];
	int sfd, ok = 0;

	sfd = agent_connect(path);
	if (sfd < 0)
		return 0;
	out[0] = AG_INFO;
	if (sock_send(sfd, out, 1) < 0 || sock_recv(sfd, out, sizeof out) < 0 ||
	    out[0] != AG_OK) {
		close(sfd);
		return 0;
	}
	close(sfd);
	if (get_be64(out + 2) != (uint64_t)dev ||
	    get_be64(out + 10) != (uint64_t)ino) {
		warnx("agent serves a different safe, ignoring it");
		return 0;
	}
	if (out[1] == AG_INFO_BADKEY)
		warnx("agent holds a key that does not open this safe, ignoring it");
	else if (out[1] == AG_INFO_OK)
		ok = 1;
	return ok;
}

static int
agent_request(int sfd, uint8_t cmd, const char *name)
{
	uint8_t hdr[1 + 4];
	size_t len = strlen(name);

	hdr[0] = cmd;
	put_be32(hdr + 1, (uint32_t)len);
	if (len == 0 || len >= PATH_MAX)
		return -1;
	if (sock_send(sfd, hdr, sizeof hdr) < 0 || sock_send(sfd, name, len) < 0)
		return -1;
	return 0;
}

static int
agent_decrypt(const char *path, const char *name, int out, struct safe *s)
{
	uint8_t hdr[1 + 4];
	uint32_t len;
	int sfd, rc = -1;

	sfd = agent_connect(path);
	if (sfd < 0)
		return -1;
	if (agent_request(sfd, AG_DECRYPT, name) < 0 ||
	    sock_recv(sfd, hdr, sizeof hdr) < 0 || hdr[0] != AG_OK)
		goto done;
	len = get_be32(hdr + 1);
	while (len > 0) {
		size_t n = len < (uint32_t)s->message.sz ?
		    len : (size_t)s->message.sz;

		if (sock_recv(sfd, s->message.buf, n) < 0 ||
		    xwrite(out, s->message.buf, n) != (ssize_t)n)
			goto done;
		len -= (uint32_t)n;
	}
	rc = 0;
done:
	close(sfd);
	return rc;
}

/* encrypt through the agent */
static int
agent_encrypt(const char *path, const char *name, int in, int out,
    struct safe *s)
{
	uint8_t hb[1 + SAFE_HEADER_SIZE +
	    crypto_secretstream_xchacha20poly1305_HEADERBYTES];
	uint8_t salt[SAFE_SALT_SIZE], lenb[4];
	unsigned version;
	int sfd, eof = 0, rc = -1;

	sfd = agent_connect(path);
	if (sfd < 0)
		return -1;
	if (agent_request(sfd, AG_ENCRYPT, name) < 0 ||
	    sock_recv(sfd, hb, sizeof hb) < 0 || hb[0] != AG_OK)
		goto done;
	/* the agent's key must be this store's key (same salt) */
	if (safe_hdr_parse(hb + 1, salt, &version) < 0 ||
	    sodium_memcmp(salt, s->crypto.salt, sizeof salt) != 0)
		goto done;
	if (xwrite(out, hb + 1, sizeof hb - 1) != (ssize_t)(sizeof hb - 1))
		goto done;

	for (;;) {
		ssize_t n = xread(in, s->message.buf, SAFE_CHUNK_SIZE, &eof);
		size_t want;

		if (n < 0)
			goto done;
		/* 0x11 agents do not pad the last frame */
		want = (size_t)n;
		if (version == SAFE_FORMAT && n < SAFE_CHUNK_SIZE)
			want = safe_pad_bucket((size_t)n);
		want += crypto_secretstream_xchacha20poly1305_ABYTES;
		put_be32(lenb, (uint32_t)n);
		if (sock_send(sfd, lenb, 4) < 0 ||
		    (n > 0 && sock_send(sfd, s->message.buf, (size_t)n) < 0))
			goto done;
		if (sock_recv(sfd, s->cipher.buf, want) < 0 ||
		    xwrite(out, s->cipher.buf, want) != (ssize_t)want)
			goto done;
		if (n < SAFE_CHUNK_SIZE)
			break;
	}
	rc = 0;
done:
	close(sfd);
	sodium_memzero(s->message.buf, (size_t)s->message.sz);
	return rc;
}


static int
forget_agent(const char *sockp)
{
	char sp[PATH_MAX];
	struct sockaddr_un addr;
	struct stat lst;
	struct ucred cred;
	struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
	socklen_t clen = sizeof cred;
	uint8_t ack = 0;
	int sfd;

	if (sockp && *sockp) {
		if (snprintf(sp, sizeof sp, "%s", sockp) >= (int)sizeof sp) {
			warnx("SAFE_SOCK path too long");
			return 1;
		}
	} else {
		const char *xdg = getenv("XDG_RUNTIME_DIR");
		char wkp[PATH_MAX], buf[PATH_MAX];
		ssize_t n;
		int fd;

		if (!xdg || !*xdg) {
			warnx("SAFE_SOCK not set and XDG_RUNTIME_DIR unavailable");
			return 1;
		}
		if (snprintf(wkp, sizeof wkp, "%s/safe/sock", xdg)
		    >= (int)sizeof wkp) {
			warnx("well-known socket path too long");
			return 1;
		}
		fd = open(wkp, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
		if (fd < 0) {
			warn("%s", wkp);
			return 1;
		}
		n = read(fd, buf, sizeof buf - 1);
		close(fd);
		if (n <= 0) {
			warnx("%s: empty or unreadable", wkp);
			return 1;
		}
		buf[n] = '\0';
		if (buf[n - 1] == '\n')
			buf[--n] = '\0';
		if (n == 0 || (size_t)n >= sizeof sp) {
			warnx("%s: bad socket path", wkp);
			return 1;
		}
		memcpy(sp, buf, (size_t)n + 1);
	}

	if (lstat(sp, &lst) < 0) {
		if (errno == ENOENT)
			return 0;	/* no agent running */
		warn("%s", sp);
		return 1;
	}
	if (geteuid() == 0) {
		if (!S_ISSOCK(lst.st_mode)) {
			warnx("%s: not a socket", sp);
			return 1;
		}
	} else if (validate_sock_path(sp) < 0) {
		warnx("%s: insecure or invalid agent socket", sp);
		return 1;
	}
	if (sockaddr_set(&addr, sp) < 0) {
		warnx("%s: path too long", sp);
		return 1;
	}
	sfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sfd < 0) {
		warn("socket");
		return 1;
	}
	fcntl(sfd, F_SETFD, FD_CLOEXEC);
	(void)setsockopt(sfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
	if (connect(sfd, (struct sockaddr *)&addr, sizeof addr) < 0) {
		int e = errno;

		close(sfd);
		if (e == ECONNREFUSED)
			return 0;	/* stale socket: nothing to forget */
		errno = e;
		warn("connect %s", sp);
		return 1;
	}
	if (getsockopt(sfd, SOL_SOCKET, SO_PEERCRED, &cred, &clen) < 0 ||
	    cred.uid != lst.st_uid) {
		close(sfd);
		warnx("%s: agent uid does not match the socket owner", sp);
		return 1;
	}
	if (sock_send(sfd, "F", 1) < 0 || sock_recv(sfd, &ack, 1) < 0 ||
	    ack != 'K') {
		close(sfd);
		warnx("%s: agent did not acknowledge", sp);
		return 1;
	}
	close(sfd);
	return 0;
}

static void
verify_dir(const char *path)
{
	struct stat st;

	if (stat(path, &st) < 0)
		err(1, "stat: %s", path);
	if (!S_ISDIR(st.st_mode))
		errx(1, "%s is not a directory", path);
	if (st.st_uid != geteuid())
		errx(1, "%s is not owned by the current user", path);
	if (st.st_mode & 077)
		errx(1, "%s has insecure permissions (must be 0700 or tighter)", path);
}



int
main(int argc, char *argv[])
{
	int aflag = 0, bflag = 0, rflag = 0, kflag = 0, fflag = 0;
	int Fflag = 0, oflag = 0;
	int fd = -1, haskey = 0, hasmaster = 1, ttyfd, have_tty = 0, dirfd;
	int rc = 0, recovery = 0, useagent = 0;
	struct stat dirst;
	char *prompt, *secret, *sockp, *safe = safe_dir;
        #define SAFE_PW_MAX 256
                char passphrase[SAFE_PW_MAX], verifyphrase[SAFE_PW_MAX];
	char safe_abs[PATH_MAX];
	ssize_t pplen, vplen = 0;
	struct safe s;

	safe   = getenv("SAFE_DIR");
	sockp  = getenv("SAFE_SOCK");
	prompt = "password:";


	signal(SIGPIPE, SIG_IGN);
	atexit(rm_pending_tmp);
	signal(SIGINT, on_term_signal);
	signal(SIGTERM, on_term_signal);
	signal(SIGHUP, on_term_signal);

	memcpy(&s.crypto, &crypto_defaults, sizeof(s.crypto));
	s.cipher.buf = NULL; s.cipher.sz = 0;
	s.message.buf = NULL; s.message.sz = 0;

	ARGBEGIN {
	case 'f':
		fflag = 1;

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
	case 'F':
		Fflag = 1;
		break;
	case 'o':
		oflag = 1;
		break;
	default:
		usage();
	} ARGEND


	if (Fflag) {
		if (aflag || rflag || bflag || kflag || fflag || oflag ||
		    argc != 0)
			usage();
		return forget_agent(sockp);
	}

	if (!safe)
		safe = safe_dir;
	if ((rflag && argc > 1) || (!rflag && argc != 1))
		usage();

	if (oflag && !rflag) {
		warnx("-o requires -r");
		return 1;
	}

	if (sodium_init() < 0)
		return -1;

#ifdef _DEBUG
	warnx("WARNING: _DEBUG build - seccomp/Landlock/core-dumps disabled");
#endif

#ifdef SANDBOX
	if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) < 0)
		warn("prctl PR_SET_DUMPABLE");
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
		warn("prctl PR_SET_NO_NEW_PRIVS");
#endif

	if (sodium_mlock(&s, sizeof(s)) < 0 ||
	    sodium_mlock(&passphrase, sizeof(passphrase)) < 0 ||
	    sodium_mlock(&verifyphrase, sizeof(verifyphrase)) < 0) {
		if (!getenv("SAFE_UNSAFE_MLOCK"))
			errx(1, "sodium_mlock failed (set SAFE_UNSAFE_MLOCK=1 to ignore)");
		warnx("sodium_mlock failed, continuing anyway");
	}

#ifndef _DEBUG
	{
		struct rlimit rlim;
		rlim.rlim_cur = rlim.rlim_max = 0;
		if (setrlimit(RLIMIT_CORE, &rlim) < 0)
			err(1, "setrlimit RLIMIT_CORE");
	}
#endif

	if (mkdir(safe, 0700) < 0) {
		if (errno != EEXIST)
			err(1, "mkdir: %s", safe);
	} else if (safe[0] != '/')
		warnx("created new safe directory %s relative to the current "
		    "directory; set SAFE_DIR to pin it", safe);

	if (!realpath(safe, safe_abs))
		err(1, "realpath: %s", safe);


	dirfd = open(safe_abs, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
	if (dirfd < 0)
		err(1, "open %s", safe_abs);

	if (fstat(dirfd, &dirst) < 0)
		err(1, "fstat %s", safe_abs);

	safe_alloc(&s.message, (ssize_t)s.crypto.xchacha20poly1305_bufsiz);
	safe_alloc(&s.cipher,
	    (ssize_t)s.crypto.xchacha20poly1305_bufsiz +
	    crypto_secretstream_xchacha20poly1305_ABYTES);

	if ((ttyfd = open(_PATH_TTY, O_RDWR | O_NOCTTY | O_CLOEXEC)) < 0) {
		kflag = 1;
	} else {
		have_tty = 1;
		close(ttyfd);
	}

#ifdef __OpenBSD__
	{
		const char *ap = getenv("SAFE_ASKPASS");
		if (!ap)
			ap = askpass_path;
		if (unveil(_PATH_TTY, "rw") == -1)
			err(1, "unveil %s", _PATH_TTY);
		if (unveil(safe, "rwc") == -1)
			err(1, "unveil %s", safe);
		if (ap && unveil(ap, "rx") == -1)
			warn("unveil %s", ap);
	}
	if (sockp)
		if (unveil(sockp, "rw") == -1)
			err(1, "unveil %s", sockp);
	if (pledge("stdio rpath wpath cpath unix tty proc", NULL) < 0)
		err(1, "pledge");
#endif

	if (fchdir(dirfd) < 0)
		err(1, "fchdir");
	close(dirfd);
	verify_dir(".");

#ifdef SANDBOX
	if (install_seccomp(1) < 0)
		err(1, "seccomp phase 1");
#endif


	fd = open(master_entry, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
	if (fd < 0) {
		if (errno != ENOENT)
			err(1, "%s", master_entry);
		hasmaster = 0;
	}
	if (hasmaster) {
		if (readheader(fd, &s.crypto) < 0)
			errx(1, "invalid master header: %s", master_entry);
		close(fd);
		fd = -1;
	}


	recovery = hasmaster && aflag && fflag && argc == 1 &&
	           argv[0] && strcmp(argv[0], master_entry) == 0;


	/* use the agent only if it serves this store */
	if (sockp && !rflag && hasmaster && !recovery) {
		if (validate_sock_path(sockp) < 0)
			warnx("SAFE_SOCK=%s: insecure or invalid path, ignoring", sockp);
		else if (agent_usable(sockp, dirst.st_dev, dirst.st_ino))
			useagent = 1;
	}

	if (!hasmaster) {
		pplen = readpass(prompt, passphrase, sizeof(passphrase), kflag, bflag);
		if (pplen < 0) { rc = 1; goto out; }

		vplen = readpass("verify:", verifyphrase, sizeof(verifyphrase), kflag, bflag);
		if (vplen < 0) { rc = 1; goto out; }

		if (pplen != vplen ||
		    sodium_memcmp(passphrase, verifyphrase, (size_t)pplen) != 0) {
			fprintf(stderr, "password mismatch\n");
			rc = 1; goto out;
		}
		sodium_memzero(verifyphrase, sizeof(verifyphrase));

		randombytes_buf(s.crypto.salt, sizeof(s.crypto.salt));
		if (deriv(passphrase, &s) < 0) {
			warn("crypto_pwhash");
			rc = 1; goto out;
		}

		if (write_master_atomic(&s, master_entry, master_entry,
		        "safe", 4) < 0) {
			warn("write master entry");
			rc = 1; goto out;
		}
		haskey = 1;
	}

	if (!haskey && !useagent) {
		pplen = readpass(prompt, passphrase, sizeof(passphrase), kflag, bflag);
		if (pplen < 0) { rc = 1; goto out; }
		if (recovery) {
			vplen = readpass("verify:", verifyphrase,
			    sizeof(verifyphrase), kflag, bflag);
			if (vplen < 0) { rc = 1; goto out; }
			if (pplen != vplen ||
			    sodium_memcmp(passphrase, verifyphrase,
			        (size_t)pplen) != 0) {
				fprintf(stderr, "password mismatch\n");
				rc = 1; goto out;
			}
			sodium_memzero(verifyphrase, sizeof(verifyphrase));
		}
		if (deriv(passphrase, &s) < 0) {
			warn("crypto_pwhash");
			rc = 1; goto out;
		}
		haskey = 1;
	}
	sodium_memzero(passphrase, sizeof(passphrase));

#ifdef SANDBOX
	if (install_landlock(safe_abs, have_tty ? _PATH_TTY : NULL, NULL) < 0) {
		warn("landlock");
		rc = 1; goto out;
	}
	if (install_seccomp(2) < 0) {
		warn("seccomp phase 2");
		rc = 1; goto out;
	}
#endif
#ifdef __OpenBSD__
	if (pledge("stdio rpath wpath cpath unix tty", NULL) < 0)
		err(1, "pledge (tight)");
#endif


	if (recovery) {
		warnx("recovery mode: skipping master password verification");
	} else if (!useagent) {
		fd = open(master_entry, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
		if (fd < 0) {
			warn("%s", master_entry);
			rc = 1; goto out;
		}
		lseek(fd, SAFE_HEADER_SIZE, SEEK_SET);
		if (trydecrypt(&s, fd, master_entry) < 0) {
			fprintf(stderr, "incorrect master password\n");
			rc = 1; goto out;
		}
		close(fd);
		fd = -1;
	}

	if (rflag && recovery) {
		warnx("recovery mode: key not pushed to the agent; run safe -r again");
	} else if (rflag) {
		if (!sockp) {
			warnx("SAFE_SOCK variable is not set");
			rc = 1; goto out;
		}
		if (pushkey(&s, sockp, oflag) < 0) {
			warn("pushkey");
			rc = 1;
		}
	}

	secret = argv[0];
	if (!secret)
		goto out;

	if (!valid_secret_path(secret)) {
		warnx("invalid secret path: %s", secret);
		rc = 1; goto out;
	}

	if (aflag && !fflag && strcmp(secret, master_entry) == 0) {
		warnx("refusing to overwrite the master entry (use -f to force)");
		rc = 1; goto out;
	}

	if (aflag) {
		mkdir_p(dirname(secret), 0700);
		if (write_secret_atomic(&s, secret, secret, STDIN_FILENO, fflag,
		    useagent ? sockp : NULL) < 0) {
			if (errno == EEXIST)
				warnx("%s: already exists (use -f to overwrite)", secret);
			else
				warn("writesecret");
			rc = 1; goto out;
		}
	} else if (strcmp(secret, master_entry) == 0) {
		/* the master entry holds no secret; the password was verified */
		if (useagent && agent_decrypt(sockp, secret, STDOUT_FILENO, &s) < 0) {
			warnx("agent refused");
			rc = 1; goto out;
		}
	} else if (useagent) {
		if (agent_decrypt(sockp, secret, STDOUT_FILENO, &s) < 0) {
			if (access(secret, F_OK) < 0 && errno == ENOENT)
				warnx("%s: no such entry", secret);
			else
				warnx("agent could not decrypt %s (locked, outside "
				    "its -p prefix, or the entry does not "
				    "authenticate)", secret);
			rc = 1; goto out;
		}
	} else {
		fd = open(secret, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
		if (fd < 0) {
			warn("%s", secret);
			rc = 1; goto out;
		}

		if (readheader(fd, &s.crypto) < 0) {
			warnx("invalid header: %s", secret);
			rc = 1; goto out;
		}

		if (readsecret(&s, fd, STDOUT_FILENO, secret) < 0) {
			warnx("decryption failed");
			rc = 1; goto out;
		}
		close(fd);
		fd = -1;
	}

out:
	if (fd >= 0)
		close(fd);
	safe_release(&s.message);
	safe_release(&s.cipher);
	sodium_memzero(&s, sizeof(s));
	sodium_memzero(passphrase, sizeof(passphrase));
	sodium_memzero(verifyphrase, sizeof(verifyphrase));
	(void)sodium_munlock(&s, sizeof(s));
	(void)sodium_munlock(passphrase, sizeof(passphrase));
	(void)sodium_munlock(verifyphrase, sizeof(verifyphrase));
	return rc;
}
