
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

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
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "config.h"	/* before the SANDBOX gate below: it defines SAFE_SANDBOX */

/*
 * Clipboard backend, fixed at build time since the binary is setuid:
 * WL_BACKEND_RS (default) or WL_BACKEND_C for GNOME.
 */
#if defined(WL_COPY_NO_SENSITIVE) && !defined(WL_BACKEND_C)
# define WL_BACKEND_C
#endif
#if defined(WL_BACKEND_C) && defined(WL_BACKEND_RS)
# error "define only one of WL_BACKEND_C and WL_BACKEND_RS"
#endif
#if !defined(WL_BACKEND_C) && !defined(WL_BACKEND_RS)
# define WL_BACKEND_RS
#endif

#ifdef __linux__
# include <sys/auxv.h>
# include <sys/prctl.h>
# include <sys/syscall.h>
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
# ifndef LANDLOCK_RULE_PATH_BENEATH
#  define LANDLOCK_RULE_PATH_BENEATH 1
# endif
# ifndef LANDLOCK_ACCESS_FS_EXECUTE
#  define LANDLOCK_ACCESS_FS_EXECUTE     (1ULL << 0)
#  define LANDLOCK_ACCESS_FS_WRITE_FILE  (1ULL << 1)
#  define LANDLOCK_ACCESS_FS_READ_FILE   (1ULL << 2)
#  define LANDLOCK_ACCESS_FS_READ_DIR    (1ULL << 3)
#  define LANDLOCK_ACCESS_FS_REMOVE_DIR  (1ULL << 4)
#  define LANDLOCK_ACCESS_FS_REMOVE_FILE (1ULL << 5)
#  define LANDLOCK_ACCESS_FS_MAKE_CHAR   (1ULL << 6)
#  define LANDLOCK_ACCESS_FS_MAKE_DIR    (1ULL << 7)
#  define LANDLOCK_ACCESS_FS_MAKE_REG    (1ULL << 8)
#  define LANDLOCK_ACCESS_FS_MAKE_SOCK   (1ULL << 9)
#  define LANDLOCK_ACCESS_FS_MAKE_FIFO   (1ULL << 10)
#  define LANDLOCK_ACCESS_FS_MAKE_BLOCK  (1ULL << 11)
#  define LANDLOCK_ACCESS_FS_MAKE_SYM    (1ULL << 12)
# endif
#endif 

#include <sodium.h>

#if defined(__linux__) && !defined(SANDBOX) && !defined(_DEBUG) && !defined(FUZZING)
# warning "safe-fill-host: built WITHOUT Landlock/seccomp (SAFE_SANDBOX unset?)"
#endif

#define MSG_MAX     (64 * 1024)
#define SECRET_MAX  (64 * 1024)
#define SECRET_BUF  (SECRET_MAX + 1)



static int
read_msg(char *buf, size_t bufsiz)
{
	uint32_t len;

	if (fread(&len, sizeof len, 1, stdin) != 1)
		return -1;
	if (len == 0 || len >= bufsiz)
		return -1;
	if (fread(buf, 1, len, stdin) != len)
		return -1;
	buf[len] = '\0';
	return (int)len;
}

static void
send_msg(const char *json)
{
	uint32_t len = (uint32_t)strlen(json);
	fwrite(&len, sizeof len, 1, stdout);
	fwrite(json, 1, len, stdout);
	fflush(stdout);
}

static void
reply_error(const char *code)
{
	char buf[128];
	snprintf(buf, sizeof buf, "{\"success\":false,\"error\":\"%s\"}", code);
	send_msg(buf);
}



static int
send_all(int fd, const void *buf, size_t len)
{
	const uint8_t *p = buf;

	while (len > 0) {
		ssize_t n = write(fd, p, len);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (n == 0)
			return -1;
		p += n;
		len -= (size_t)n;
	}
	return 0;
}

static int
recv_all(int fd, void *buf, size_t len)
{
	uint8_t *p = buf;

	while (len > 0) {
		ssize_t n = read(fd, p, len);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (n == 0)
			return -1;
		p += n;
		len -= (size_t)n;
	}
	return 0;
}


static int
already_being_traced(void)
{
#if !defined(__linux__)
	return 0;
#else
	char buf[4096];
	const char *p;
	int fd;
	ssize_t n;

	fd = open("/proc/self/status", O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return 0;
	n = read(fd, buf, sizeof buf - 1);
	close(fd);
	if (n <= 0)
		return 0;
	buf[n] = '\0';

	p = strstr(buf, "\nTracerPid:");
	if (!p)
		return 0;
	p += strlen("\nTracerPid:");
	while (*p == ' ' || *p == '\t')
		p++;
	return *p != '0' && *p != '\n' && *p != '\0';
#endif
}


static void
close_fds_from(int lowfd)
{
#ifdef __linux__
# ifdef SYS_close_range
	if (syscall(SYS_close_range, (unsigned)lowfd, ~0U, 0) == 0)
		return;
# endif
#endif
	{
		long maxfd = sysconf(_SC_OPEN_MAX);
		int fd;
		if (maxfd < 0 || maxfd > 65536)
			maxfd = 65536;
		for (fd = lowfd; fd < (int)maxfd; fd++)
			close(fd);
	}
}


static int
check_peer_uid(int fd, uid_t expected_uid)
{
#if defined(__linux__)
	{
		struct ucred cred;
		socklen_t len = sizeof cred;

		if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED,
		    &cred, &len) < 0)
			return -1;
		if (cred.uid != expected_uid)
			return -1;
	}
#else
	{
		uid_t uid;
		gid_t gid;

		if (getpeereid(fd, &uid, &gid) < 0)
			return -1;
		if (uid != expected_uid)
			return -1;
	}
#endif
	return 0;
}



static int
json_get_string(const char *json, const char *field, char *out, size_t outmax)
{
	char pat[64];
	snprintf(pat, sizeof pat, "\"%s\":\"", field);

	const char *p = strstr(json, pat);
	if (!p)
		return -1;
	p += strlen(pat);

	size_t i = 0;
	while (*p && *p != '"') {
		if (*p == '\\')
			return -1;
		if (i + 1 >= outmax)
			return -1;
		out[i++] = *p++;
	}
	if (*p != '"')
		return -1;
	out[i] = '\0';
	return i > 0 ? 0 : -1;
}



#include "proto.h"
#include "validate.h"




enum { OP_FILL, OP_LIST, OP_USER };

static int
parse_request(const char *msg, int *op, char *path, size_t pathmax,
              const char **err)
{
	char origin[256], username[256], opname[16];
	int n;

	*op = OP_FILL;
	if (strstr(msg, "\"op\":")) {
		if (json_get_string(msg, "op", opname, sizeof opname) < 0) {
			*err = "bad_request";
			return -1;
		}
		if (!strcmp(opname, "list"))
			*op = OP_LIST;
		else if (!strcmp(opname, "user"))
			*op = OP_USER;
		else if (strcmp(opname, "fill") != 0) {
			*err = "bad_op";
			return -1;
		}
	}

	if (json_get_string(msg, "origin", origin, sizeof origin) < 0 ||
	    (*op == OP_FILL &&
	     json_get_string(msg, "username", username, sizeof username) < 0)) {
		*err = "bad_request";
		return -1;
	}

	if (!valid_origin(origin)) {
		*err = "bad_origin";
		return -1;
	}

	if (*op != OP_FILL) {
		n = snprintf(path, pathmax, "passwords/%s", origin);
		if (n < 0 || (size_t)n >= pathmax) {
			*err = "path_too_long";
			return -1;
		}
		return 0;
	}

	if (!valid_username(username)) {
		*err = "bad_username";
		return -1;
	}

	n = snprintf(path, pathmax, "passwords/%s/%s", origin, username);
	if (n < 0 || (size_t)n >= pathmax) {
		*err = "path_too_long";
		return -1;
	}

	return 0;
}



static int
validate_sock_path(const char *path, uid_t *expected_uid)
{
	struct stat st;
	uid_t sock_uid;
	char dir[PATH_MAX];
	char *slash;
	size_t plen;

	plen = strlen(path);
	if (plen == 0 || plen >= sizeof dir)
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

	if (st.st_uid == 0)
		return -1;
	if (AGENT_SOCK_PATH[0] == '\0' && st.st_uid != geteuid())
		return -1;
	sock_uid = st.st_uid;

	if (lstat(dir, &st) < 0)
		return -1;
	if (!S_ISDIR(st.st_mode))
		return -1;
	if (st.st_mode & 027)
		return -1;
	if (AGENT_SOCK_PATH[0] == '\0' && st.st_uid != geteuid())
		return -1;
	if (st.st_uid == 0)
		return -1;

	if (expected_uid)
		*expected_uid = sock_uid;
	return 0;
}



static int
find_sock(char *buf, size_t bufsiz, uid_t *expected_uid)
{
	if (AGENT_SOCK_PATH[0]) {
		size_t l = strlen(AGENT_SOCK_PATH);
		if (l >= bufsiz)
			return -1;
		if (validate_sock_path(AGENT_SOCK_PATH, expected_uid) < 0)
			return -1;
		memcpy(buf, AGENT_SOCK_PATH, l + 1);
		return 0;
	}

	{
		const char *env = getenv("SAFE_SOCK");
		if (env && *env) {
			size_t l = strlen(env);
			if (l >= bufsiz)
				return -1;
			if (validate_sock_path(env, expected_uid) < 0)
				return -1;
			memcpy(buf, env, l + 1);
			return 0;
		}
	}

	{
		const char *xdg = getenv("XDG_RUNTIME_DIR");
		char path[PATH_MAX];
		int fd;
		ssize_t n;

		if (!xdg || !*xdg)
			return -1;
		if (snprintf(path, sizeof path, "%s/safe/sock", xdg)
		    >= (int)sizeof path)
			return -1;

		fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
		if (fd < 0)
			return -1;
		n = read(fd, buf, bufsiz - 1);
		close(fd);
		if (n <= 0)
			return -1;
		buf[n] = '\0';
		if (buf[n - 1] == '\n')
			buf[--n] = '\0';
		if (n == 0)
			return -1;

		if (validate_sock_path(buf, expected_uid) < 0)
			return -1;

		return 0;
	}
}



/* send cmd for path, read 'K' len[4] data */
static ssize_t
agent_request(const char *sock, uid_t expected_uid, char cmd,
              const char *path, char *out, size_t outmax)
{
	int sfd;
	struct sockaddr_un addr;
	uint8_t len_be[4];
	size_t plen;
	size_t total = 0;
	ssize_t n;

	plen = strlen(path);
	if (plen == 0 || plen >= PATH_MAX)
		return -1;
	if (strlen(sock) >= sizeof addr.sun_path)
		return -1;

	sfd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (sfd < 0)
		return -1;

	memset(&addr, 0, sizeof addr);
	addr.sun_family = AF_UNIX;
	memcpy(addr.sun_path, sock, strlen(sock) + 1);

	if (connect(sfd, (struct sockaddr *)&addr, sizeof addr) < 0)
		goto err;

	if (check_peer_uid(sfd, expected_uid) < 0)
		goto err;

	len_be[0] = (uint8_t)(plen >> 24);
	len_be[1] = (uint8_t)(plen >> 16);
	len_be[2] = (uint8_t)(plen >> 8);
	len_be[3] = (uint8_t)(plen);

	if (send_all(sfd, &cmd, 1) < 0)
		goto err;
	if (send_all(sfd, len_be, 4) < 0)
		goto err;
	if (send_all(sfd, path, plen) < 0)
		goto err;

	{
		uint8_t hdr[5];
		uint32_t want;

		if (recv_all(sfd, hdr, sizeof hdr) < 0 || hdr[0] != 'K')
			goto err;
		want = ((uint32_t)hdr[1] << 24) | ((uint32_t)hdr[2] << 16) |
		    ((uint32_t)hdr[3] << 8) | hdr[4];
		if ((want == 0 && cmd != 'L') || want > outmax)
			goto err;
		while (total < want) {
			n = read(sfd, out + total, want - total);
			if (n < 0) {
				if (errno == EINTR)
					continue;
				goto err;
			}
			if (n == 0)
				goto err;	/* truncated */
			total += (size_t)n;
		}
	}
	close(sfd);
	return (ssize_t)total;

err:
	close(sfd);
	return -1;
}



#ifdef SANDBOX

static int
landlock_add_path(int ruleset, const char *path, uint64_t access)
{
	struct landlock_path_beneath_attr pb;
	int fd, rc;

	fd = open(path, O_PATH | O_CLOEXEC);
	if (fd < 0) {
		warn("landlock open %s", path);
		return -1;
	}
	pb.allowed_access = access;
	pb.parent_fd = fd;
	rc = syscall(SYS_landlock_add_rule, ruleset,
	    LANDLOCK_RULE_PATH_BENEATH, &pb, 0);
	if (rc < 0)
		warn("landlock_add_rule %s", path);
	close(fd);
	return rc;
}


/* skip paths absent on this system */
static int
landlock_add_path_opt(int ruleset, const char *path, uint64_t rights)
{
	if (access(path, F_OK) < 0 && errno == ENOENT)
		return 0;
	return landlock_add_path(ruleset, path, rights);
}


static int
install_landlock(const char *sockpath)
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
	char xdg_user[PATH_MAX];
	char sock_abs[PATH_MAX];
	char sock_dir[PATH_MAX];
	char *slash;
	int ruleset, rc, ok;

	{
		/* ENOMSG means supported */
		long abi = syscall(SYS_landlock_create_ruleset, NULL, 0, 1U);

		if (abi < 0) {
#ifdef ALLOW_NO_LANDLOCK
			if (errno == ENOSYS || errno == EOPNOTSUPP)
				return 0;
#endif
			warn("landlock unavailable");
			return -1;
		}
	}
	ra.handled_access_fs = handled;

	ruleset = syscall(SYS_landlock_create_ruleset, &ra, sizeof(ra), 0);
	if (ruleset < 0) {
		warn("landlock_create_ruleset");
		return -1;
	}


	if (sockpath[0] != '/') {
		char cwd[PATH_MAX];
		if (!getcwd(cwd, sizeof cwd) ||
		    snprintf(sock_abs, sizeof sock_abs, "%s/%s", cwd, sockpath)
		    >= (int)sizeof sock_abs) {
			warn("landlock: socket path resolve");
			close(ruleset);
			return -1;
		}
	} else {
		snprintf(sock_abs, sizeof sock_abs, "%s", sockpath);
	}


	if (landlock_add_path(ruleset, sock_abs,
	    LANDLOCK_ACCESS_FS_READ_FILE) < 0) {
		close(ruleset);
		return -1;
	}
	snprintf(sock_dir, sizeof sock_dir, "%s", sock_abs);
	slash = strrchr(sock_dir, '/');
	if (slash && slash != sock_dir) {
		*slash = '\0';
		if (landlock_add_path(ruleset, sock_dir,
		    LANDLOCK_ACCESS_FS_READ_DIR) < 0) {
			close(ruleset);
			return -1;
		}
	}


	if (landlock_add_path(ruleset, WL_COPY_PATH,
	    LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE) < 0) {
		close(ruleset);
		return -1;
	}


	snprintf(xdg_user, sizeof xdg_user, "/run/user/%u",
	    (unsigned)getuid());
	(void)landlock_add_path_opt(ruleset, xdg_user,
	    LANDLOCK_ACCESS_FS_READ_FILE  |
	    LANDLOCK_ACCESS_FS_WRITE_FILE |
	    LANDLOCK_ACCESS_FS_READ_DIR   |
	    LANDLOCK_ACCESS_FS_MAKE_SOCK);


	if (landlock_add_path(ruleset, "/dev/null",
	    LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_WRITE_FILE) < 0) {
		close(ruleset);
		return -1;
	}
	(void)landlock_add_path_opt(ruleset, "/dev/urandom",
	    LANDLOCK_ACCESS_FS_READ_FILE);
#ifdef WL_BACKEND_C
	/* wl-clipboard (C) buffers its input in /tmp/wl-copy-buffer-XXXXXX/stdin */
	(void)landlock_add_path_opt(ruleset, "/tmp",
	    LANDLOCK_ACCESS_FS_READ_FILE   | LANDLOCK_ACCESS_FS_WRITE_FILE |
	    LANDLOCK_ACCESS_FS_MAKE_DIR    | LANDLOCK_ACCESS_FS_MAKE_REG   |
	    LANDLOCK_ACCESS_FS_REMOVE_FILE | LANDLOCK_ACCESS_FS_REMOVE_DIR);
#endif


	(void)landlock_add_path_opt(ruleset, "/etc/ld.so.cache",
	    LANDLOCK_ACCESS_FS_READ_FILE);
	(void)landlock_add_path_opt(ruleset, "/etc/ld-musl-x86_64.path",
	    LANDLOCK_ACCESS_FS_READ_FILE);
	(void)landlock_add_path_opt(ruleset, "/lib",
	    LANDLOCK_ACCESS_FS_EXECUTE |
	    LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR);
	(void)landlock_add_path_opt(ruleset, "/lib64",
	    LANDLOCK_ACCESS_FS_EXECUTE |
	    LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR);
	(void)landlock_add_path_opt(ruleset, "/usr/lib",
	    LANDLOCK_ACCESS_FS_EXECUTE |
	    LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR);
	(void)landlock_add_path_opt(ruleset, "/usr/lib64",
	    LANDLOCK_ACCESS_FS_EXECUTE |
	    LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR);


	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
		close(ruleset);
		return -1;
	}
	rc = syscall(SYS_landlock_restrict_self, ruleset, 0);
	ok = rc;
	close(ruleset);
	return ok < 0 ? -1 : 0;
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
	RET(SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA));
	RET(SECCOMP_RET_ALLOW);

#ifdef __NR_socketpair
	JEQ(__NR_socketpair, 0, 4);
	LD(offsetof(struct seccomp_data, args[0]));
	JEQ(AF_UNIX, 1, 0);
	RET(SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA));
	RET(SECCOMP_RET_ALLOW);
#endif


	JEQ(__NR_prctl, 0, 5);
	LD(offsetof(struct seccomp_data, args[0]));
	JEQ(PR_SET_NO_NEW_PRIVS, 2, 0);
	JEQ(PR_SET_SECCOMP, 1, 0);
	RET(SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA));
	RET(SECCOMP_RET_ALLOW);


	AS(read); AS(write); AS(close); AS(lseek);
	AS(pread64); AS(pwrite64); AS(readv); AS(writev);
	AS(preadv); AS(pwritev);


	AS(openat);
#ifdef __NR_open
	AS(open);
#endif
#if defined(WL_BACKEND_C) && defined(__NR_creat)
	AS(creat);
#endif
	AS(newfstatat); AS(fstat);
#ifdef __NR_stat
	AS(stat);
#endif
#ifdef __NR_lstat
	AS(lstat);
#endif
	AS(statx);
#ifdef __NR_readlink
	AS(readlink);
#endif
	AS(readlinkat);
#ifdef __NR_access
	AS(access);
#endif
	AS(faccessat);
#ifdef __NR_faccessat2
	AS(faccessat2);
#endif
	AS(getcwd); AS(chdir); AS(fchdir);
	AS(getdents64);
#ifdef __NR_fchmod
	AS(fchmod);
#endif
#ifdef __NR_fchmodat
	AS(fchmodat);
#endif
	JEQ(__NR_ioctl, 0, 8);
	LD(offsetof(struct seccomp_data, args[1]));
	JEQ(0x5401, 5, 0);	/* TCGETS */
	JEQ(0x5421, 4, 0);	/* FIONBIO */
	JEQ(0x541b, 3, 0);	/* FIONREAD */
	JEQ(0x5451, 2, 0);	/* FIOCLEX */
	JEQ(0x5450, 1, 0);	/* FIONCLEX */
	RET(SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA));
	RET(SECCOMP_RET_ALLOW);
	AS(fcntl);


	AS(mmap); AS(munmap); AS(mprotect); AS(mremap); AS(madvise);
	AS(brk); AS(mlock); AS(munlock);


	AS(rt_sigaction); AS(rt_sigprocmask); AS(rt_sigreturn);
	AS(rt_sigpending); AS(rt_sigtimedwait);
	AS(sigaltstack);
	AS(tgkill);


#ifdef __NR_poll
	AS(poll);
#endif
	AS(ppoll);
#ifdef __NR_select
	AS(select);
#endif
	AS(pselect6);
#ifdef __NR_epoll_create1
	AS(epoll_create1);
# ifdef __NR_epoll_create
	AS(epoll_create);
# endif
	AS(epoll_ctl);
#ifdef __NR_epoll_wait
	AS(epoll_wait);
#endif
	AS(epoll_pwait);
#endif
#ifdef __NR_eventfd2
	AS(eventfd2);
#endif


	AS(getpid); AS(getppid); AS(gettid);
	AS(getuid); AS(geteuid); AS(getgid); AS(getegid); AS(getgroups);
	AS(uname);


	AS(set_tid_address); AS(set_robust_list); AS(rseq);
	AS(membarrier); AS(futex); AS(sched_yield);
	AS(sched_getaffinity);


	AS(prlimit64); AS(getrlimit); AS(setrlimit);
	AS(getrusage);
#ifdef __NR_umask
	AS(umask);
#endif
#ifdef __NR_sysinfo
	AS(sysinfo);
#endif


	AS(clock_gettime); AS(clock_nanosleep); AS(nanosleep);
#ifdef __NR_time
	AS(time);
#endif
#ifdef __NR_gettimeofday
	AS(gettimeofday);
#endif


	AS(getrandom);


	AS(connect); AS(sendto); AS(recvfrom);
	AS(sendmsg); AS(recvmsg);
	AS(shutdown);
	AS(getsockname); AS(getpeername);
	AS(setsockopt); AS(getsockopt);
#ifdef __NR_accept
	AS(accept);
#endif
#ifdef __NR_accept4
	AS(accept4);
#endif
#ifdef __NR_bind
	AS(bind);
#endif
#ifdef __NR_listen
	AS(listen);
#endif


#ifdef __NR_pipe
	AS(pipe);
#endif
#ifdef __NR_pipe2
	AS(pipe2);
#endif
	AS(dup);
#ifdef __NR_dup2
	AS(dup2);
#endif
	AS(dup3);


#ifdef __NR_memfd_create
	AS(memfd_create);
#endif
#ifdef __NR_ftruncate
	AS(ftruncate);
#endif


#ifdef __NR_fork
	AS(fork);
#endif
#ifdef __NR_vfork
	AS(vfork);
#endif
#ifdef __NR_clone3
	AS(clone3);
#endif
	AS(clone); AS(execve);
	AS(wait4);
#ifdef __NR_waitid
	AS(waitid);
#endif
	AS(setsid);
	AS(setresuid); AS(setresgid);


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
	AS(fsync); AS(fdatasync);


	AS(exit); AS(exit_group);


#ifdef __NR_arch_prctl
	AS(arch_prctl);
#endif


	RET(SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA));

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




/* setuid/setgid exec: ignore the caller's environment */
static int
privileged_exec(void)
{
#if defined(__linux__)
	return getauxval(AT_SECURE) != 0;
#elif defined(__OpenBSD__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__APPLE__)
	return issetugid();
#else
	return getuid() != geteuid() || getgid() != getegid();
#endif
}

static int
drop_to_real_uid(void)
{
	uid_t r = getuid(), old_e = geteuid();
	gid_t g = getgid(), old_eg = getegid();

#if defined(__OpenBSD__) || defined(__APPLE__)
	if (setgid(g) < 0)
		return -1;
	if (setuid(r) < 0)
		return -1;
#else
	if (setresgid(g, g, g) < 0)
		return -1;
	if (setresuid(r, r, r) < 0)
		return -1;
#endif
	/* the privileged ids must be gone for good, not just inactive */
	if (old_eg != g && (setegid(old_eg) == 0 || getegid() != g))
		return -1;
	if (old_e != r && (seteuid(old_e) == 0 || geteuid() != r))
		return -1;
	return 0;
}

static char **
wl_env(void)
{
	static char xdg[64], wd[256];
	static char *envp[3];
	const char *v;
	int n = 0;

	snprintf(xdg, sizeof xdg, "XDG_RUNTIME_DIR=/run/user/%u",
	    (unsigned)getuid());
	envp[n++] = xdg;
	v = getenv("WAYLAND_DISPLAY");
	if (v && *v && !strchr(v, '/') &&
	    snprintf(wd, sizeof wd, "WAYLAND_DISPLAY=%s", v) < (int)sizeof wd)
		envp[n++] = wd;
	envp[n] = NULL;
	return envp;
}

/* fds 0-2 to /dev/null; wl-copy (C) aborts if one is closed */
static int
stdio_to_null(int also_stdin)
{
	int nul = open("/dev/null", O_RDWR);
	int bad;

	if (nul < 0)
		return -1;
	bad = (also_stdin && dup2(nul, STDIN_FILENO) < 0) ||
	    dup2(nul, STDOUT_FILENO) < 0 || dup2(nul, STDERR_FILENO) < 0;
	if (nul > STDERR_FILENO)
		close(nul);
	return bad ? -1 : 0;
}

static void
wl_exec_copy(void)
{
#ifdef WL_BACKEND_C
	/* -t text/plain: skips MIME sniffing, which execs xdg-mime/gio/realpath */
	execle(WL_COPY_PATH, "wl-copy", "--paste-once",
	       "-t", "text/plain", (char *)NULL, wl_env());
#else
	execle(WL_COPY_PATH, "wl-copy", "--paste-once", "--sensitive",
	       (char *)NULL, wl_env());
#endif
}

static int
run_wl_copy(const char *secret, size_t len)
{
	int p[2];
	pid_t pid;
	size_t written = 0;
	int status = -1;

	if (pipe(p) < 0)
		return -1;

	pid = fork();
	if (pid < 0) {
		close(p[0]);
		close(p[1]);
		return -1;
	}
	if (pid == 0) {
		dup2(p[0], STDIN_FILENO);
		close(p[0]);
		close(p[1]);
		setsid();
		if (stdio_to_null(0) < 0)
			_exit(126);

		if (drop_to_real_uid() < 0)
			_exit(126);

		wl_exec_copy();
		_exit(127);
	}
	close(p[0]);

	while (written < len) {
		ssize_t n = write(p[1], secret + written, len - written);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		written += (size_t)n;
	}
	close(p[1]);

	while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
		continue;

	return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -1;
}

static void
schedule_wl_clear(void)
{
	pid_t pid = fork();

	if (pid != 0)
		return;

	setsid();
	if (stdio_to_null(1) < 0)
		_exit(126);

	/* drop first: nothing below needs the host's ids */
	if (drop_to_real_uid() < 0)
		_exit(126);

	sleep(WL_CLEAR_DELAY_SEC);

	execle(WL_COPY_PATH, "wl-copy", "--clear", (char *)NULL, wl_env());
	_exit(127);
}



#ifndef FUZZING
/* only '"' needs escaping in a valid username */
static int
json_str(char *out, size_t outmax, const char *name, size_t n)
{
	size_t o = strlen(out);

	if (o + 2 * n + 3 >= outmax)
		return -1;
	out[o++] = '"';
	for (size_t i = 0; i < n; i++) {
		if (name[i] == '"')
			out[o++] = '\\';
		out[o++] = name[i];
	}
	out[o++] = '"';
	out[o] = '\0';
	return 0;
}

static int
json_names(char *out, size_t outmax, char *names, size_t len)
{
	char *p = names, *end = names + len;
	int count = 0;

	if (strlen(out) + 2 >= outmax)
		return -1;
	strcat(out, "[");
	while (p < end) {
		char *nl = memchr(p, '\n', (size_t)(end - p));
		size_t n = nl ? (size_t)(nl - p) : (size_t)(end - p);

		p[n] = '\0';
		if (valid_username(p)) {
			if (count && strlen(out) + 1 < outmax)
				strcat(out, ",");
			if (json_str(out, outmax, p, n) < 0)
				return -1;
			count++;
		}
		p += n + 1;
	}
	if (strlen(out) + 1 >= outmax)
		return -1;
	strcat(out, "]");
	return count;
}

/* list, or copy the only username (no delayed clear) */
static int
do_names(int op, const char *sock, uid_t expected_uid, const char *path)
{
	static char names[AG_L_MAX_BYTES + 1];
	static char reply[2 * AG_L_MAX_BYTES + 128];
	ssize_t n;

	n = agent_request(sock, expected_uid, AG_LIST, path, names,
	    AG_L_MAX_BYTES);
	if (n < 0) {
		reply_error("agent_failed");
		return 1;
	}
	names[n] = '\0';

	if (op == OP_USER && n > 0 && !memchr(names, '\n', (size_t)n) &&
	    valid_username(names)) {
		if (run_wl_copy(names, (size_t)n) < 0) {
			reply_error("clipboard_failed");
			return 1;
		}
		strcpy(reply, "{\"success\":true,\"username\":");
		if (json_str(reply, sizeof reply, names, (size_t)n) < 0) {
			reply_error("agent_failed");
			return 1;
		}
		strcat(reply, "}");
		send_msg(reply);
		return 0;
	}

	if (op == OP_LIST)
		strcpy(reply, "{\"success\":true,\"usernames\":");
	else
		snprintf(reply, sizeof reply,
		    "{\"success\":false,\"error\":\"%s\",\"usernames\":",
		    n == 0 ? "no_entry" : "ambiguous");
	if (json_names(reply, sizeof reply, names, (size_t)n) < 0) {
		reply_error("agent_failed");
		return 1;
	}
	strcat(reply, "}");
	send_msg(reply);
	return op == OP_LIST ? 0 : 1;
}

int
main(void)
{
	char msg[MSG_MAX];
	char path[PATH_MAX];
	char sock[PATH_MAX];
	uid_t expected_uid = (uid_t)-1;
	char *secret;
	ssize_t n;
	const char *err = NULL;
	int parse_rc, op;

	struct rlimit rlim = { 0, 0 };
	if (setrlimit(RLIMIT_CORE, &rlim) < 0)
		return 1;


#ifdef __linux__
# ifndef _DEBUG

	if (!already_being_traced())
		(void)prctl(PR_SET_DUMPABLE, 0);
# endif


	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
		reply_error("prctl_failed");
		return 1;
	}
#endif

	close_fds_from(3);

	signal(SIGPIPE, SIG_IGN);

	if (sodium_init() < 0)
		return 1;


	if (find_sock(sock, sizeof sock, &expected_uid) < 0) {
		reply_error("no_agent");
		return 1;
	}

#ifdef SANDBOX

	if (install_landlock(sock) < 0) {
		reply_error("landlock_failed");
		return 1;
	}
	if (install_seccomp() < 0) {
		reply_error("seccomp_failed");
		return 1;
	}
#endif

	if (read_msg(msg, sizeof msg) < 0) {
		reply_error("bad_frame");
		return 1;
	}

	parse_rc = parse_request(msg, &op, path, sizeof path, &err);
	sodium_memzero(msg, sizeof msg);
	if (parse_rc < 0) {
		reply_error(err);
		return 1;
	}
	if (op != OP_FILL)
		return do_names(op, sock, expected_uid, path);

	secret = malloc(SECRET_BUF);
	if (!secret) {
		reply_error("oom");
		return 1;
	}
	if (sodium_mlock(secret, SECRET_BUF) < 0) {
		if (privileged_exec() || !getenv("SAFE_UNSAFE_MLOCK")) {
			free(secret);
			reply_error("mlock_failed");
			return 1;
		}
	}

	n = agent_request(sock, expected_uid, AG_DECRYPT, path, secret, SECRET_MAX);
	if (n < 0) {
		sodium_memzero(secret, SECRET_BUF);
		sodium_munlock(secret, SECRET_BUF);
		free(secret);
		reply_error("agent_failed");
		return 1;
	}
	if (n == 0) {
		sodium_memzero(secret, SECRET_BUF);
		sodium_munlock(secret, SECRET_BUF);
		free(secret);
		reply_error("empty_secret");
		return 1;
	}

	if (run_wl_copy(secret, (size_t)n) < 0) {
		sodium_memzero(secret, SECRET_BUF);
		sodium_munlock(secret, SECRET_BUF);
		free(secret);
		reply_error("clipboard_failed");
		return 1;
	}

	sodium_memzero(secret, SECRET_BUF);
	sodium_munlock(secret, SECRET_BUF);
	free(secret);

	schedule_wl_clear();

	send_msg("{\"success\":true}");
	return 0;
}
#endif 

#ifdef FUZZING
int
host_fuzz_parse(const char *msg, char *path, size_t pathmax)
{
	const char *err = NULL;
	int op;

	/* -1, or the op: OP_FILL (0) has a username, the others do not */
	if (parse_request(msg, &op, path, pathmax, &err) < 0)
		return -1;
	return op;
}
#endif 