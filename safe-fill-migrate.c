
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
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

#include <nss.h>
#include <pk11pub.h>
#include <pk11sdr.h>
#include <prerror.h>
#include <secitem.h>

#include <sodium.h>
#include <sqlite3.h>

#include "arg.h"
#include "readpassphrase.h"
#include "config.h"

#define PLAIN_MAX 8192

/* logins.json limits */
#define JSON_FILE_MAX  (32u << 20)
#define JFIELD_MAX     16384
#define JHOST_MAX      2048

extern PK11SymKey *PK11_ListFixedKeysInSlot(PK11SlotInfo *, char *, void *);

struct ctx {
	uint8_t      *key;
	char         *plainbuf;
	char         *safe_bin;
	const char   *safedir;
	const char   *switch_user;  
	int           dryrun, force;
	int           n_ok, n_fail, n_skip;
	sqlite3      *db;
};

char *argv0;

static void
usage(void)
{
	fprintf(stderr,
	    "usage: %s [-mnf] [-U user] [-s safe-dir] <profile-dir>\n"
	    "\n"
	    "  -m  migrate: decrypt saved logins and store in safe (the only\n"
	    "      mode; accepted for compatibility)\n"
	    "  -n  dry run: show what would happen, change nothing\n"
	    "  -f  overwrite existing safe entries\n"
	    "  -U  switch to <user> for safe(1) invocations (hardened profile)\n"
	    "  -s  path to safe directory (default: $SAFE_DIR or .secrets)\n"
	    "\n"
	    "Requires SAFE_SOCK to point at a running safe-agent with the\n"
	    "key loaded (eval $(safe-agent -t 900) and safe -r). With -U, the doas\n"
	    "rule must keep SAFE_SOCK ('setenv { SAFE_SOCK }', or 'keepenv\n"
	    "{ SAFE_SOCK }' on doas versions that need it) and permit safe(1).\n",
	    argv0);
	exit(1);
}

static PK11SymKey *
get_session_key_copy(PK11SlotInfo *slot, const char *name)
{
	char keyname[64];
	PK11SymKey *token_key, *wrapper, *session;
	uint8_t wrapped[40];
	SECItem wrapped_item = { siBuffer, wrapped, sizeof wrapped };

	if (snprintf(keyname, sizeof keyname, "%s", name)
	    >= (int)sizeof keyname)
		return NULL;

	token_key = PK11_ListFixedKeysInSlot(slot, keyname, NULL);
	if (!token_key)
		return NULL;

	wrapper = PK11_KeyGen(slot, CKM_AES_KEY_GEN, NULL, 16, NULL);
	if (!wrapper) {
		PK11_FreeSymKey(token_key);
		return NULL;
	}

	if (PK11_WrapSymKey(CKM_AES_KEY_WRAP_KWP, NULL, wrapper, token_key,
	                    &wrapped_item) != SECSuccess) {
		PK11_FreeSymKey(wrapper);
		PK11_FreeSymKey(token_key);
		return NULL;
	}

	session = PK11_UnwrapSymKey(wrapper, CKM_AES_KEY_WRAP_KWP, NULL,
	                            &wrapped_item, CKM_AES_GCM,
	                            CKA_ENCRYPT | CKA_DECRYPT, 32);

	PK11_FreeSymKey(wrapper);
	PK11_FreeSymKey(token_key);
	return session;
}

static int
read_key_bytes(PK11SymKey *key, uint8_t *out, size_t out_len)
{
	SECItem *k;

	if (PK11_ExtractKeyValue(key) != SECSuccess)
		return -1;
	k = PK11_GetKeyData(key);
	if (!k || k->len != out_len)
		return -1;
	memcpy(out, k->data, out_len);
	return 0;
}

/* open key4.db read-only and log in */
static PK11SlotInfo *
nss_open(const char *profile)
{
	char password_buf[256] = "";
	PK11SlotInfo *slot;

	if (NSS_Initialize(profile, "", "", "secmod.db",
	    NSS_INIT_READONLY) != SECSuccess) {
		warnx("NSS_Init(%s): %s", profile,
		      PORT_ErrorToString(PORT_GetError()));
		return NULL;
	}

	slot = PK11_GetInternalKeySlot();
	if (!slot) {
		warnx("PK11_GetInternalKeySlot: %s",
		      PORT_ErrorToString(PORT_GetError()));
		NSS_Shutdown();
		return NULL;
	}

	if (PK11_NeedLogin(slot) && !PK11_IsLoggedIn(slot, NULL) &&
	    PK11_CheckUserPassword(slot, "") != SECSuccess) {
		if (!readpassphrase("Firefox primary password: ",
		                    password_buf, sizeof password_buf,
		                    RPP_ECHO_OFF | RPP_REQUIRE_TTY)) {
			warnx("no TTY for primary password prompt");
			goto fail;
		}
		if (PK11_CheckUserPassword(slot, password_buf) != SECSuccess) {
			warnx("PK11_CheckUserPassword: %s",
			      PORT_ErrorToString(PORT_GetError()));
			goto fail;
		}
	}
	sodium_memzero(password_buf, sizeof password_buf);
	return slot;
fail:
	sodium_memzero(password_buf, sizeof password_buf);
	PK11_FreeSlot(slot);
	NSS_Shutdown();
	return NULL;
}

static void
nss_close(PK11SlotInfo *slot)
{
	PK11_FreeSlot(slot);
	NSS_Shutdown();
}

/* logins.db: the AES-256-GCM key stored in key4.db as "as-logins-key" */
static int
extract_key_from_nss(const char *profile, uint8_t *key)
{
	PK11SlotInfo *slot;
	PK11SymKey *session;
	int rc = -1;

	if (!(slot = nss_open(profile)))
		return -1;
	session = get_session_key_copy(slot, "as-logins-key");
	if (!session) {
		warnx("key4.db has no \"as-logins-key\" for logins.db");
		goto out;
	}
	rc = read_key_bytes(session, key, 32);
	PK11_FreeSymKey(session);
out:
	nss_close(slot);
	return rc;
}

static int
split_jwe(char *s, char *parts[5])
{
	int n = 0;
	parts[n++] = s;
	for (char *p = s; *p; p++) {
		if (*p == '.') {
			*p = '\0';
			if (n >= 5)
				return -1;
			parts[n++] = p + 1;
		}
	}
	return n;
}

static ssize_t
decrypt_jwe(const char *jwe, const uint8_t *key, char *out, size_t outmax)
{
	char *copy, *parts[5];
	const uint8_t *aad;
	size_t aad_len, iv_len = 16, ct_len = PLAIN_MAX, tag_len = 16;
	uint8_t iv[16], ct[PLAIN_MAX], tag[16];

	copy = strdup(jwe);
	if (!copy)
		return -1;

	if (split_jwe(copy, parts) != 5)
		goto err;

	aad = (const uint8_t *)parts[0];
	aad_len = strlen(parts[0]);

	if (parts[1][0] != '\0')
		goto err;

	if (sodium_base642bin(iv, sizeof iv, parts[2], strlen(parts[2]),
	                      NULL, &iv_len, NULL,
	                      sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0
	    || iv_len != 12)
		goto err;
	if (sodium_base642bin(ct, sizeof ct, parts[3], strlen(parts[3]),
	                      NULL, &ct_len, NULL,
	                      sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0)
		goto err;
	if (sodium_base642bin(tag, sizeof tag, parts[4], strlen(parts[4]),
	                      NULL, &tag_len, NULL,
	                      sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0
	    || tag_len != 16)
		goto err;

	if (ct_len + 1 > outmax)
		goto err;

	if (crypto_aead_aes256gcm_decrypt_detached((uint8_t *)out, NULL,
	        ct, ct_len, tag, aad, aad_len, iv, key) != 0)
		goto err;

	free(copy);
	return (ssize_t)ct_len;

err:
	free(copy);
	return -1;
}

static int
json_unescape(char *s, size_t len, size_t *outlen)
{
	char *s0 = s;
	char *end = s + len;
	char *dst = s;

	while (s < end) {
		if (*s != '\\') {
			*dst++ = *s++;
			continue;
		}
		s++;
		if (s >= end)
			return -1;
		switch (*s) {
		case '"': case '\\': case '/':
			*dst++ = *s++;
			break;
		case 'b': *dst++ = '\b'; s++; break;
		case 'f': *dst++ = '\f'; s++; break;
		case 'n': *dst++ = '\n'; s++; break;
		case 'r': *dst++ = '\r'; s++; break;
		case 't': *dst++ = '\t'; s++; break;
		case 'u': {
			unsigned int b;
			if (s + 5 > end) return -1;
			if (s[1] != '0' || s[2] != '0') return -1;
			if (sscanf(s + 3, "%2x", &b) != 1) return -1;
			if (b == 0 || b >= 0x80) return -1;
			*dst++ = (char)b;
			s += 5;
			break;
		}
		default:
			return -1;
		}
	}
	*dst = '\0';
	*outlen = (size_t)(dst - s0);
	return 0;
}

static int
parse_login(char *json, char **user, size_t *ulen,
            char **pass, size_t *plen)
{
	char *p = json;

	*user = *pass = NULL;
	*ulen = *plen = 0;

	while (*p) {
		char *kstart, *vstart;
		size_t klen, vlen;

		if (*p != '"') { p++; continue; }
		kstart = ++p;
		while (*p && *p != '"') p++;
		if (!*p) break;
		klen = (size_t)(p - kstart);
		*p++ = '\0';
		while (*p == ' ' || *p == '\t') p++;
		if (*p != ':') continue;
		p++;
		while (*p == ' ' || *p == '\t') p++;
		if (*p != '"') continue;
		vstart = ++p;
		while (*p && *p != '"') {
			if (*p == '\\' && p[1]) p++;
			p++;
		}
		if (!*p) break;
		vlen = (size_t)(p - vstart);
		*p++ = '\0';

		if ((klen == 1 && kstart[0] == 'u') ||
		    (klen == 8 && !memcmp(kstart, "username", 8))) {
			*user = vstart; *ulen = vlen;
		} else if ((klen == 1 && kstart[0] == 'p') ||
		           (klen == 8 && !memcmp(kstart, "password", 8))) {
			*pass = vstart; *plen = vlen;
		}
	}

	if (!*user || !*pass)
		return -1;
	if (json_unescape(*user, *ulen, ulen) < 0)
		return -1;
	if (json_unescape(*pass, *plen, plen) < 0)
		return -1;
	if (*ulen == 0)
		return -1;
	return 0;
}

static int
canonicalize_origin(const char *in, char *out, size_t outlen)
{
	const char *p = in;
	const char *suffix;
	size_t i, slen;
	int https = 0;

	if (!strncmp(p, "https://", 8)) {
		p += 8;
		https = 1;
	} else if (!strncmp(p, "http://", 7)) {
		p += 7;
	}

	i = 0;
	while (*p && *p != '/' && i + 1 < outlen) {
		char c = *p++;
		if (c >= 'A' && c <= 'Z')
			c = (char)(c - 'A' + 'a');
		out[i++] = c;
	}
	out[i] = '\0';

	if (i == 0)
		return -1;

	suffix = https ? ":443" : ":80";
	slen = strlen(suffix);
	if (i >= slen && strcmp(out + i - slen, suffix) == 0)
		out[i - slen] = '\0';

	return 0;
}

#include "validate.h"

static int
plain_http_origin(const char *origin)
{
	const char *h;
	size_t n;

	if (strncmp(origin, "http://", 7) != 0)
		return 0;
	h = origin + 7;
	n = strcspn(h, ":/");
	/* loopback is fine */
	return !(n == 9 && (strncmp(h, "localhost", 9) == 0 ||
	    strncmp(h, "127.0.0.1", 9) == 0));
}

static int
trusted_bin(const char *path, struct stat *st)
{
	if (stat(path, st) < 0)
		return 0;
	if (!S_ISREG(st->st_mode))
		return 0;
	if (!(st->st_mode & 0111))
		return 0;
	if (st->st_uid != 0 && st->st_uid != geteuid())
		return 0;
	if (st->st_mode & (S_IWGRP | S_IWOTH))
		return 0;
	return 1;
}

static char *
find_safe(void)
{
	const char *env = getenv("SAFE_BIN");
	const char *path;
	char *copy, *tok, *save = NULL;

	if (env && *env) {

		struct stat est;

		if (trusted_bin(env, &est))
			return strdup(env);
		return NULL;
	}

	path = getenv("PATH");
	if (!path)
		path = "/usr/local/bin:/usr/bin:/bin";

	copy = strdup(path);
	if (!copy)
		return NULL;

	for (tok = strtok_r(copy, ":", &save); tok;
	     tok = strtok_r(NULL, ":", &save)) {
		char cand[PATH_MAX];
		struct stat st;
		if (snprintf(cand, sizeof cand, "%s/safe", tok)
		    >= (int)sizeof cand)
			continue;
		if (trusted_bin(cand, &st)) {
			free(copy);
			return strdup(cand);
		}
	}
	free(copy);
	return NULL;
}

static void
exec_safe(struct ctx *ctx, char *const extra[])
{
	if (ctx->switch_user && *ctx->switch_user) {
		char *argv[10];
		int n = 0;

		argv[n++] = "doas";
		argv[n++] = "-u";
		argv[n++] = (char *)ctx->switch_user;
		argv[n++] = ctx->safe_bin;
		if (ctx->safedir) {
			argv[n++] = "-s";
			argv[n++] = (char *)ctx->safedir;
		}
		for (int i = 0; extra[i] && n < 9; i++)
			argv[n++] = extra[i];
		argv[n] = NULL;
		execvp("doas", argv);
	} else {
		char *argv[10];
		int n = 0;

		argv[n++] = ctx->safe_bin;
		if (ctx->safedir) {
			argv[n++] = "-s";
			argv[n++] = (char *)ctx->safedir;
		}
		for (int i = 0; extra[i] && n < 9; i++)
			argv[n++] = extra[i];
		argv[n] = NULL;
		execv(ctx->safe_bin, argv);
	}
	_exit(127);
}

static int
migrate_one(struct ctx *ctx, const char *host, const char *user,
            const char *pass, size_t passlen)
{
	char path[PATH_MAX];
	int pfd[2];
	pid_t pid;
	size_t written = 0;
	int status = -1, ec;

	if (!valid_origin(host) || !valid_username(user)) {
		printf("skip: %s/%s: not representable for safe-fill-host\n",
		       host, user);
		return 1;
	}
	if (snprintf(path, sizeof path, "passwords/%s/%s", host, user)
	    >= (int)sizeof path) {
		printf("skip: %s/%s: path too long\n", host, user);
		return 1;
	}
	if (!valid_secret_path(path)) {
		printf("skip: %s: invalid path\n", path);
		return 1;
	}

	if (ctx->dryrun) {
		printf("would migrate: %s\n", path);
		return 0;
	}

	if (pipe(pfd) < 0) {
		warn("pipe");
		return -1;
	}

	pid = fork();
	if (pid < 0) {
		warn("fork");
		close(pfd[0]);
		close(pfd[1]);
		return -1;
	}
	if (pid == 0) {
		char *argv[3];
		int n = 0;

		if (dup2(pfd[0], STDIN_FILENO) < 0)
			_exit(127);
		close(pfd[0]);
		close(pfd[1]);

		argv[n++] = ctx->force ? "-af" : "-a";
		argv[n++] = path;
		argv[n] = NULL;
		exec_safe(ctx, argv);
	}
	close(pfd[0]);

	while (written < passlen) {
		ssize_t n = write(pfd[1], pass + written, passlen - written);
		if (n < 0) {
			if (errno == EINTR) continue;
			break;
		}
		written += (size_t)n;
	}
	close(pfd[1]);

	while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
		continue;

	ec = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
	if (ec != 0 || written != passlen) {
		printf("failed: %s (safe exited %d, wrote %zu/%zu)\n",
		       path, ec, written, passlen);
		return -1;
	}
	printf("migrated: %s\n", path);
	return 0;
}

static void
process_entry(struct ctx *ctx, const char *origin, const char *user,
              const char *pass, size_t plen)
{
	char host[256];
	int r;

	if (plen == 0) {
		printf("skip: %s: empty password\n", origin);
		ctx->n_skip++;
		return;
	}
	if (plain_http_origin(origin)) {
		printf("skip: %s: plain-http origin\n", origin);
		ctx->n_skip++;
		return;
	}
	if (canonicalize_origin(origin, host, sizeof host) < 0) {
		printf("skip: %s: invalid origin\n", origin);
		ctx->n_skip++;
		return;
	}
	r = migrate_one(ctx, host, user, pass, plen);
	if (r < 0) ctx->n_fail++;
	else if (r > 0) ctx->n_skip++;
	else ctx->n_ok++;
}

/* minimal logins.json reader */
struct jp {
	const char *p, *end;
	int depth;
};

static void
jp_ws(struct jp *j)
{
	while (j->p < j->end &&
	    (*j->p == ' ' || *j->p == '\t' || *j->p == '\n' || *j->p == '\r'))
		j->p++;
}

static int
jp_peek(struct jp *j)
{
	jp_ws(j);
	return j->p < j->end ? (unsigned char)*j->p : -1;
}

static int
hexval(int c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

static int
jp_string(struct jp *j, char *out, size_t outmax)
{
	size_t n = 0;

	if (jp_peek(j) != '"')
		return -1;
	j->p++;
	while (j->p < j->end) {
		unsigned char c = (unsigned char)*j->p++;
		unsigned int u = 0;

		if (c == '"') {
			if (out)
				out[n] = '\0';
			return 0;
		}
		if (c < 0x20)
			return -1;
		if (c == '\\') {
			if (j->p >= j->end)
				return -1;
			c = (unsigned char)*j->p++;
			switch (c) {
			case '"': case '\\': case '/': break;
			case 'b': c = '\b'; break;
			case 'f': c = '\f'; break;
			case 'n': c = '\n'; break;
			case 'r': c = '\r'; break;
			case 't': c = '\t'; break;
			case 'u':
				if (j->end - j->p < 4)
					return -1;
				for (int k = 0; k < 4; k++) {
					int h = hexval((unsigned char)j->p[k]);
					if (h < 0)
						return -1;
					u = u << 4 | (unsigned int)h;
				}
				j->p += 4;
				if (out && (u == 0 || u >= 0x80))
					return -1;
				c = (unsigned char)u;
				break;
			default:
				return -1;
			}
		}
		if (out) {
			if (n + 1 >= outmax)
				return -1;
			out[n] = (char)c;
		}
		n++;
	}
	return -1;
}

static int
jp_skip(struct jp *j)
{
	int c = jp_peek(j);

	if (c < 0)
		return -1;
	if (c == '"')
		return jp_string(j, NULL, 0);
	if (c == '{' || c == '[') {
		int close = c == '{' ? '}' : ']';

		if (++j->depth > 64)
			return -1;
		j->p++;
		if (jp_peek(j) == close) {
			j->p++;
			j->depth--;
			return 0;
		}
		for (;;) {
			if (close == '}') {
				if (jp_string(j, NULL, 0) < 0 || jp_peek(j) != ':')
					return -1;
				j->p++;
			}
			if (jp_skip(j) < 0)
				return -1;
			c = jp_peek(j);
			if (c == ',') {
				j->p++;
				continue;
			}
			if (c == close) {
				j->p++;
				j->depth--;
				return 0;
			}
			return -1;
		}
	}
	{
		const char *s0 = j->p;

		while (j->p < j->end && *j->p &&
		    strchr("+-.0123456789eEtrufalsn", *j->p))
			j->p++;
		return j->p > s0 ? 0 : -1;
	}
}

/* a string field that may also be null; *have says which */
static int
jp_opt_string(struct jp *j, char *out, size_t outmax, int *have)
{
	if (jp_peek(j) == 'n') {
		*have = 0;
		return jp_skip(j);
	}
	*have = 1;
	return jp_string(j, out, outmax);
}

typedef void (*login_cb)(void *, const char *, const char *, const char *,
                         long);

static int
jp_logins(struct jp *j, login_cb cb, void *arg)
{
	static char host[JHOST_MAX], eu[JFIELD_MAX], ep[JFIELD_MAX];
	char key[256];
	int c;

	if (jp_peek(j) != '[')
		return -1;
	j->p++;
	if (jp_peek(j) == ']') {
		j->p++;
		return 0;
	}
	for (;;) {
		int hh = 0, hu = 0, hp = 0;
		long enc = -1;

		if (jp_peek(j) != '{')
			return -1;
		j->p++;
		if (jp_peek(j) == '}') {
			j->p++;
		} else for (;;) {
			if (jp_string(j, key, sizeof key) < 0 || jp_peek(j) != ':')
				return -1;
			j->p++;
			if (!strcmp(key, "hostname")) {
				if (jp_opt_string(j, host, sizeof host, &hh) < 0)
					return -1;
			} else if (!strcmp(key, "encryptedUsername")) {
				if (jp_opt_string(j, eu, sizeof eu, &hu) < 0)
					return -1;
			} else if (!strcmp(key, "encryptedPassword")) {
				if (jp_opt_string(j, ep, sizeof ep, &hp) < 0)
					return -1;
			} else if (!strcmp(key, "encType")) {
				char num[16];
				const char *s0;
				size_t len;

				jp_ws(j);
				s0 = j->p;
				if (jp_skip(j) < 0)
					return -1;
				len = (size_t)(j->p - s0);
				if (len > 0 && len < sizeof num) {
					memcpy(num, s0, len);
					num[len] = '\0';
					enc = strtol(num, NULL, 10);
				}
			} else if (jp_skip(j) < 0) {
				return -1;
			}
			c = jp_peek(j);
			if (c == ',') {
				j->p++;
				continue;
			}
			if (c != '}')
				return -1;
			j->p++;
			break;
		}
		cb(arg, hh ? host : "", hu ? eu : "", hp ? ep : "", enc);
		c = jp_peek(j);
		if (c == ',') {
			j->p++;
			continue;
		}
		if (c != ']')
			return -1;
		j->p++;
		return 0;
	}
}

static int
parse_logins_json(const char *buf, size_t len, login_cb cb, void *arg)
{
	struct jp j = { buf, buf + len, 0 };
	char key[256];
	int found = 0, c;

	if (jp_peek(&j) != '{')
		return -1;
	j.p++;
	if (jp_peek(&j) == '}') {
		j.p++;
	} else for (;;) {
		if (jp_string(&j, key, sizeof key) < 0 || jp_peek(&j) != ':')
			return -1;
		j.p++;
		if (!strcmp(key, "logins") && !found) {
			if (jp_logins(&j, cb, arg) < 0)
				return -1;
			found = 1;
		} else if (jp_skip(&j) < 0) {
			return -1;
		}
		c = jp_peek(&j);
		if (c == ',') {
			j.p++;
			continue;
		}
		if (c != '}')
			return -1;
		j.p++;
		break;
	}
	if (jp_peek(&j) != -1)
		return -1;
	return found ? 0 : -1;
}

/* base64 SDR blob -> plaintext; free *out with SECITEM_ZfreeItem */
static int
sdr_decrypt(const char *b64, SECItem *out)
{
	static unsigned char bin[JFIELD_MAX];
	size_t binlen;
	const char *end;
	SECItem in;

	out->data = NULL;
	out->len = 0;
	if (sodium_base642bin(bin, sizeof bin, b64, strlen(b64), NULL,
	    &binlen, &end, sodium_base64_VARIANT_ORIGINAL) != 0 || *end)
		return -1;
	in.type = siBuffer;
	in.data = bin;
	in.len = (unsigned int)binlen;
	if (PK11SDR_Decrypt(&in, out, NULL) != SECSuccess) {
		out->data = NULL;
		out->len = 0;
		return -1;
	}
	return 0;
}

static void
json_login(void *arg, const char *origin, const char *eu, const char *ep,
           long enc)
{
	struct ctx *ctx = arg;
	SECItem u, p;
	char user[256];
	size_t plen;

	if (!*origin || !*eu || !*ep) {
		printf("skip: %s: incomplete login\n", *origin ? origin : "?");
		ctx->n_skip++;
		return;
	}
	if (enc != 1) {
		printf("skip: %s: unsupported encType %ld\n", origin, enc);
		ctx->n_skip++;
		return;
	}
	if (sdr_decrypt(eu, &u) < 0) {
		printf("skip: %s: decrypt failed\n", origin);
		ctx->n_skip++;
		return;
	}
	if (u.len == 0 || u.len >= sizeof user || memchr(u.data, 0, u.len)) {
		printf("skip: %s: %s username\n", origin,
		       u.len == 0 ? "empty" : "unusable");
		ctx->n_skip++;
		SECITEM_ZfreeItem(&u, PR_FALSE);
		return;
	}
	memcpy(user, u.data, u.len);
	user[u.len] = '\0';
	SECITEM_ZfreeItem(&u, PR_FALSE);

	if (sdr_decrypt(ep, &p) < 0) {
		printf("skip: %s: decrypt failed\n", origin);
		ctx->n_skip++;
		return;
	}
	if (p.len >= PLAIN_MAX) {
		printf("skip: %s: password too long\n", origin);
		ctx->n_skip++;
		SECITEM_ZfreeItem(&p, PR_FALSE);
		return;
	}
	plen = p.len;
	memcpy(ctx->plainbuf, p.data, plen);
	SECITEM_ZfreeItem(&p, PR_FALSE);	/* zeroes p.len too */

	process_entry(ctx, origin, user, ctx->plainbuf, plen);
	sodium_memzero(ctx->plainbuf, PLAIN_MAX);
	sodium_memzero(user, sizeof user);
}

/* 1 if logins.db has live logins, 0 if not (or no such table), -1 on error */
static int
db_has_logins(const char *dbpath)
{
	sqlite3 *db = NULL;
	sqlite3_stmt *st = NULL;
	int n = 0;

	if (sqlite3_open_v2(dbpath, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
		sqlite3_close(db);
		return -1;
	}
	if (sqlite3_prepare_v2(db, "SELECT count(*) FROM loginsL "
	    "WHERE is_deleted=0 AND secFields<>''", -1, &st, NULL) == SQLITE_OK &&
	    sqlite3_step(st) == SQLITE_ROW)
		n = sqlite3_column_int(st, 0);
	sqlite3_finalize(st);
	sqlite3_close(db);
	return n > 0;
}

static char *
read_small_file(const char *path, size_t *lenp)
{
	struct stat st;
	char *buf;
	size_t got = 0;
	int fd;

	if ((fd = open(path, O_RDONLY | O_NOFOLLOW)) < 0)
		return NULL;
	if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode) ||
	    st.st_size <= 0 || (uintmax_t)st.st_size > JSON_FILE_MAX ||
	    !(buf = malloc((size_t)st.st_size))) {
		close(fd);
		return NULL;
	}
	while (got < (size_t)st.st_size) {
		ssize_t n = read(fd, buf + got, (size_t)st.st_size - got);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			break;
		got += (size_t)n;
	}
	close(fd);
	*lenp = got;
	return buf;
}

static int
row_cb_migrate(void *arg, int argc, char **argv, char **col)
{
	struct ctx *ctx = arg;
	const char *origin = NULL, *secfields = NULL;
	ssize_t ptlen;
	char *user, *pass;
	size_t ulen, plen;

	for (int i = 0; i < argc; i++) {
		if (col[i] && !strcmp(col[i], "origin")) origin = argv[i];
		if (col[i] && !strcmp(col[i], "secFields")) secfields = argv[i];
	}
	if (!origin || !*origin || !secfields || !*secfields)
		return 0;

	ptlen = decrypt_jwe(secfields, ctx->key, ctx->plainbuf, PLAIN_MAX);
	if (ptlen < 0) {
		printf("skip: %s: decrypt failed\n", origin);
		ctx->n_skip++;
		return 0;
	}
	ctx->plainbuf[ptlen] = '\0';

	if (parse_login(ctx->plainbuf, &user, &ulen, &pass, &plen) < 0) {
		printf("skip: %s: parse failed\n", origin);
		ctx->n_skip++;
		sodium_memzero(ctx->plainbuf, PLAIN_MAX);
		return 0;
	}
	process_entry(ctx, origin, user, pass, plen);
	sodium_memzero(ctx->plainbuf, PLAIN_MAX);
	return 0;
}

int
main(int argc, char *argv[])
{
	struct ctx ctx = {0};
	uint8_t key[32];
	char plainbuf[PLAIN_MAX];
	char dbpath[PATH_MAX], jsonpath[PATH_MAX];
	const char *profile;
	int use_json = 0;
	char *safedir = NULL;
	sqlite3 *db = NULL;
	const char *sock;
	struct stat st;
	int open_flags;
	int rc = 0;

	/* keep our lines in order with the safe(1) children's stderr */
	setvbuf(stdout, NULL, _IOLBF, 0);

	ARGBEGIN {
	case 'm': break;
	case 'b':
		errx(1, "-b (blank) was removed; once fills work, remove the "
		     "migrated logins in Firefox (about:logins)");
	case 'n': ctx.dryrun = 1;          break;
	case 'f': ctx.force  = 1;          break;
	case 'U': ctx.switch_user = EARGF(usage()); break;
	case 's': safedir = EARGF(usage()); break;
	default:  usage();
	} ARGEND

	if (argc != 1)
		usage();
	profile = argv[0];

	if (!safedir)
		safedir = getenv("SAFE_DIR");
	if (!safedir)
		safedir = safe_dir;
	if (setenv("SAFE_DIR", safedir, 1) < 0)
		err(1, "setenv SAFE_DIR");
	ctx.safedir = safedir;

	sock = getenv("SAFE_SOCK");
	if (!sock || !*sock)
		errx(1, "SAFE_SOCK not set\n"
		        "run eval $(safe-agent -t 900) and safe -r first");

	if (!ctx.switch_user) {
		if (stat(sock, &st) < 0)
			err(1, "SAFE_SOCK=%s", sock);
		if (!S_ISSOCK(st.st_mode))
			errx(1, "SAFE_SOCK=%s is not a socket", sock);
		if (st.st_uid != geteuid())
			errx(1, "SAFE_SOCK=%s is not owned by you", sock);

		{
			char sd[PATH_MAX];
			char *slash;
			size_t slen = strlen(sock);
			if (slen >= sizeof sd)
				errx(1, "SAFE_SOCK path too long");
			memcpy(sd, sock, slen + 1);
			slash = strrchr(sd, '/');
			if (!slash) {
				memcpy(sd, ".", 2);
			} else if (slash == sd) {
				sd[1] = 0;
			} else {
				*slash = 0;
			}
			if (lstat(sd, &st) < 0)
				err(1, "lstat %s", sd);
			if (!S_ISDIR(st.st_mode))
				errx(1, "%s is not a directory", sd);
			if (st.st_uid != geteuid())
				errx(1, "%s is not owned by you", sd);
			if (st.st_mode & 027)
				errx(1, "%s has insecure permissions", sd);
		}
	}

	/* prefer logins.db if it has logins, else logins.json */
	if (snprintf(dbpath, sizeof dbpath, "%s/logins.db", profile)
	    >= (int)sizeof dbpath ||
	    snprintf(jsonpath, sizeof jsonpath, "%s/logins.json", profile)
	    >= (int)sizeof jsonpath)
		errx(1, "profile path too long");
	if (access(dbpath, R_OK) == 0 && db_has_logins(dbpath) > 0)
		use_json = 0;
	else if (access(jsonpath, R_OK) == 0)
		use_json = 1;
	else if (access(dbpath, R_OK) == 0) {
		/* e.g. a profile Firefox made itself: nothing to do */
		printf("%s: no saved logins (empty logins.db, no logins.json)\n",
		       profile);
		return 0;
	}
	else
		errx(1, "%s: no logins.db or logins.json", profile);

	{
		struct rlimit rlim = { 0, 0 };
		if (setrlimit(RLIMIT_CORE, &rlim) < 0)
			err(1, "setrlimit RLIMIT_CORE");
	}
	signal(SIGPIPE, SIG_IGN);

	if (sodium_init() < 0)
		errx(1, "sodium_init");

	if (sodium_mlock(key, sizeof key) < 0 ||
	    sodium_mlock(plainbuf, sizeof plainbuf) < 0) {
		if (!getenv("SAFE_UNSAFE_MLOCK"))
			errx(1, "sodium_mlock failed "
			        "(set SAFE_UNSAFE_MLOCK=1 to ignore)");
		warnx("sodium_mlock failed, continuing anyway");
	}
	ctx.plainbuf = plainbuf;

	if (use_json) {
		PK11SlotInfo *slot;
		char *jbuf;
		size_t jlen;

		if (!(jbuf = read_small_file(jsonpath, &jlen)))
			err(1, "%s", jsonpath);
		ctx.safe_bin = find_safe();
		if (!ctx.safe_bin) {
			free(jbuf);
			errx(1, "no safe binary found in PATH "
			        "(set SAFE_BIN to override)");
		}
		if (!(slot = nss_open(profile))) {
			free(jbuf);
			errx(1, "cannot open the profile's key4.db");
		}
		printf("safe-fill-migrate: migrate%s\n\n",
		       ctx.dryrun ? " (dry run)" : "");
		printf("profile: %s\nsource: logins.json\nsafe dir: %s\n"
		       "agent: %s\n", profile, safedir, sock);
		if (ctx.switch_user && *ctx.switch_user)
			printf("switching to: %s for safe(1)\n",
			       ctx.switch_user);
		printf("\n");

		if (parse_logins_json(jbuf, jlen, json_login, &ctx) < 0) {
			warnx("%s: not a logins.json this tool can read",
			      jsonpath);
			rc = 1;
		}
		nss_close(slot);
		free(jbuf);

		if (ctx.dryrun) {
			printf("\n%d entries would be migrated, %d skipped\n",
			       ctx.n_ok, ctx.n_skip);
		} else {
			printf("\n%d migrated, %d failed, %d skipped\n",
			       ctx.n_ok, ctx.n_fail, ctx.n_skip);
			if (ctx.n_ok > 0)
				printf("\n"
				       "IMPORTANT: logins.json still contains the original\n"
				       "passwords.  Once fills work, remove them in Firefox\n"
				       "(about:logins).\n");
		}
		if (ctx.n_fail > 0)
			rc = 1;
		goto out;
	}

	if (!crypto_aead_aes256gcm_is_available())
		errx(1, "AES-256-GCM not available (needs AES-NI)");

	if (extract_key_from_nss(profile, key) < 0)
		errx(1, "NSS key extraction failed");

	ctx.key = key;

	printf("safe-fill-migrate: migrate%s\n\n",
	       ctx.dryrun ? " (dry run)" : "");
	printf("profile: %s\n", profile);
	printf("safe dir: %s\n", safedir);
	{
		const char *apid = getenv("SAFE_PID");
		if (apid && *apid)
			printf("agent: %s (pid %s)\n", sock, apid);
		else
			printf("agent: %s\n", sock);
	}
	if (ctx.switch_user && *ctx.switch_user)
		printf("switching to: %s for safe(1)\n", ctx.switch_user);
	printf("\n");

	open_flags = SQLITE_OPEN_READONLY;

	if (sqlite3_open_v2(dbpath, &db, open_flags, NULL) != SQLITE_OK) {
		warnx("sqlite3_open_v2(%s): %s", dbpath,
		      db ? sqlite3_errmsg(db) : "unknown");
		rc = 1;
		goto out;
	}
	ctx.db = db;

	ctx.safe_bin = find_safe();
	if (!ctx.safe_bin) {
		warnx("no safe binary found in PATH (set SAFE_BIN to override)");
		rc = 1;
		goto out;
	}

	{
		char *errmsg = NULL;

		if (sqlite3_exec(db,
		        "SELECT origin, secFields FROM loginsL "
		        "WHERE is_deleted=0 AND secFields<>''",
		        row_cb_migrate, &ctx, &errmsg) != SQLITE_OK) {
			warnx("sqlite3_exec: %s", errmsg ? errmsg : "unknown");
			sqlite3_free(errmsg);
			rc = 1;
			goto out;
		}

		if (ctx.dryrun) {
			printf("\n%d entries would be migrated, %d skipped\n",
			       ctx.n_ok, ctx.n_skip);
			if (ctx.n_ok > 0)
				printf("re-run without -n to migrate them\n");
		} else {
			printf("\n%d migrated, %d failed, %d skipped\n",
			       ctx.n_ok, ctx.n_fail, ctx.n_skip);
			if (ctx.n_ok > 0) {
				printf("\n"
				       "IMPORTANT: logins.db still contains the original passwords.\n"
				       "Once fills work, remove them in Firefox (about:logins).\n");
			}
		}
		rc = ctx.n_fail > 0 ? 1 : 0;
	}

out:
	if (db)
		sqlite3_close(db);
	free(ctx.safe_bin);
	sodium_memzero(key, sizeof key);
	sodium_memzero(plainbuf, sizeof plainbuf);
	sodium_munlock(key, sizeof key);
	sodium_munlock(plainbuf, sizeof plainbuf);
	return rc;
}
