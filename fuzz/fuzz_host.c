
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define FUZZ_MSG_MAX (64 * 1024)


extern int host_fuzz_parse(const char *msg, char *path, size_t pathmax);

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char buf[FUZZ_MSG_MAX];
	char path[PATH_MAX];

	if (size >= sizeof buf)
		size = sizeof buf - 1;


	if (size > 0)
		memcpy(buf, data, size);
	buf[size] = '\0';

	/* 0: passwords/<origin>/<user>; 1, 2: passwords/<origin> */
	int op = host_fuzz_parse(buf, path, sizeof path);

	if (op > 2)
		abort();
	if (op >= 0) {
		size_t slashes = 0;
		for (const char *p = path; *p; p++)
			if (*p == '/')
				slashes++;
		if (slashes != (op == 0 ? 2u : 1u))
			abort();
		if (strncmp(path, "passwords/", 10) != 0)
			abort();
	}

	return 0;
}
