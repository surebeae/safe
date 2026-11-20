#ifndef SAFE_VALIDATE_H
#define SAFE_VALIDATE_H


#include <limits.h>
#include <string.h>

/* relative, no empty, "." or ".." components: one spelling per entry */
static inline int
valid_secret_path(const char *path)
{
	size_t len, clen;
	const char *p, *end;

	if (!path || !*path || path[0] == '/')
		return 0;
	len = strlen(path);
	if (len >= PATH_MAX || path[len - 1] == '/')
		return 0;
	for (p = path;; p = end + 1) {
		end = strchr(p, '/');
		clen = end ? (size_t)(end - p) : strlen(p);
		if (clen == 0)
			return 0;
		if (clen == 1 && p[0] == '.')
			return 0;
		if (clen == 2 && p[0] == '.' && p[1] == '.')
			return 0;
		if (!end)
			break;
	}
	return 1;
}

static inline int
valid_origin(const char *s)
{
	const char *p;

	if (!s || !*s || strlen(s) > 253)
		return 0;
	for (p = s; *p; p++) {
		unsigned char c = (unsigned char)*p;
		if (!(c == '.' || c == ':' || c == '-' || c == '_' ||
		      (c >= '0' && c <= '9') ||
		      (c >= 'a' && c <= 'z') ||
		      (c >= 'A' && c <= 'Z')))
			return 0;
	}
	if (strstr(s, ".."))
		return 0;
	if (s[0] == '.' || s[0] == ':')
		return 0;
	return 1;
}

/* a single path component of at most 255 bytes */
static inline int
valid_username(const char *s)
{
	const char *p;

	if (!s || !*s || strlen(s) > 255)
		return 0;
	for (p = s; *p; p++) {
		unsigned char c = (unsigned char)*p;
		if (c == '/' || c == '\\' || c < 0x20 || c == 0x7f)
			return 0;
	}
	if (strstr(s, ".."))
		return 0;
	if (s[0] == '.')
		return 0;
	return 1;
}

#endif
