#ifndef SAFE_PROTO_H
#define SAFE_PROTO_H

/* shared by safe, safe-agent and safe-fill-host */

#include <limits.h>
#include <stdint.h>
#include <string.h>

#include <sodium.h>

/* on-disk format; 0x12 binds the header into the AD and pads */
#define SAFE_FORMAT        0x12u
#define SAFE_FORMAT_V11    0x11u
#define SAFE_HEADER_SIZE   40u
#define SAFE_CHUNK_SIZE    8192u
#define SAFE_SALT_SIZE     16u
#define SAFE_ARGON_MEM_KIB (crypto_pwhash_argon2id_MEMLIMIT_MODERATE / 1024)
#define SAFE_ARGON_OPS     crypto_pwhash_argon2id_OPSLIMIT_MODERATE
#define SAFE_ARGON_THREADS 1u

/* final chunk: sodium_pad to a power of two >= SAFE_PAD_MIN */
#define SAFE_PAD_MIN       256u

/* largest associated data: header + entry name */
#define SAFE_AD_MAX        (SAFE_HEADER_SIZE + PATH_MAX)

/* agent commands (first byte of every connection) */
#define AG_PUSH     'P'	/* salt[16] key[32] oneshot[1]            -> 'K'    */
#define AG_INFO     'I'	/* -> 'K' status[1] st_dev[8] st_ino[8]             */
#define AG_DECRYPT  'D'	/* len[4] path -> 'K' len[4] plaintext              */
#define AG_ENCRYPT  'E'	/* len[4] path, then chunks (see safe-agent(1))     */
#define AG_FORGET   'F'	/*                                        -> 'K'    */
#define AG_LIST     'L'	/* len[4] dir -> 'K' len[4] names, '\n'-separated   */
#define AG_OK       'K'
#define AG_READY    'O'

#define AG_KEYBLOB  (SAFE_SALT_SIZE + 32u)	/* salt + secretstream key */

/* AG_INFO status byte */
#define AG_INFO_NOKEY    0
#define AG_INFO_OK       1	/* key loaded and decrypts this store's master */
#define AG_INFO_BADKEY   2	/* key loaded, but not the key of this store   */

/* AG_LIST limits */
#define AG_L_MAX_NAMES   256
#define AG_L_MAX_BYTES   16384

/* AG_ENCRYPT limits */
#define AG_E_MAX_TOTAL   (64u * 1024u * 1024u)
#define AG_E_MAX_SECONDS 60

static inline void
put_be16(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)(v >> 8);
	p[1] = (uint8_t)v;
}

static inline void
put_be32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v >> 24);
	p[1] = (uint8_t)(v >> 16);
	p[2] = (uint8_t)(v >> 8);
	p[3] = (uint8_t)v;
}

static inline void
put_be64(uint8_t *p, uint64_t v)
{
	put_be32(p, (uint32_t)(v >> 32));
	put_be32(p + 4, (uint32_t)v);
}

static inline uint32_t
get_be32(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
	    ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static inline uint64_t
get_be64(const uint8_t *p)
{
	return ((uint64_t)get_be32(p) << 32) | get_be32(p + 4);
}

/* padded size of a final chunk of r bytes */
static inline size_t
safe_pad_bucket(size_t r)
{
	size_t b = SAFE_PAD_MIN;

	while (b < r + 1)
		b <<= 1;
	return b;
}

/* pad r bytes in place; buf holds SAFE_CHUNK_SIZE bytes */
static inline int
safe_pad_final(uint8_t *buf, size_t r, size_t *padded)
{
	size_t b;

	if (r >= SAFE_CHUNK_SIZE)
		return -1;
	b = safe_pad_bucket(r);
	memset(buf + r, 0, b - r);
	if (sodium_pad(padded, buf, r, b, SAFE_CHUNK_SIZE) != 0 || *padded != b)
		return -1;
	return 0;
}

/* unpad a final chunk; only canonical padding is accepted */
static inline int
safe_unpad_final(const uint8_t *buf, size_t padded, size_t *r)
{
	if (padded < SAFE_PAD_MIN || padded > SAFE_CHUNK_SIZE ||
	    (padded & (padded - 1)) != 0)
		return -1;
	if (sodium_unpad(r, buf, padded, padded) != 0)
		return -1;
	if (safe_pad_bucket(*r) != padded)
		return -1;
	return 0;
}

/* AD: name for 0x11, header + name for 0x12 */
static inline int
safe_ad_build(uint8_t *out, size_t outmax, const uint8_t *hdr,
    unsigned version, const char *name, size_t *adlen)
{
	size_t nl = strlen(name);

	if (version == SAFE_FORMAT_V11) {
		if (nl > outmax)
			return -1;
		memcpy(out, name, nl);
		*adlen = nl;
		return 0;
	}
	if (version != SAFE_FORMAT || nl > outmax - SAFE_HEADER_SIZE)
		return -1;
	memcpy(out, hdr, SAFE_HEADER_SIZE);
	memcpy(out + SAFE_HEADER_SIZE, name, nl);
	*adlen = SAFE_HEADER_SIZE + nl;
	return 0;
}

/* build the 40-byte CREAM header */
static inline void
safe_hdr_build(uint8_t out[SAFE_HEADER_SIZE], const uint8_t *salt)
{
	static const uint8_t magic[6] = {'C', 'R', 'E', 'A', 'M', '\1'};

	memcpy(out, magic, sizeof magic);
	put_be16(out + 6, SAFE_FORMAT);
	put_be32(out + 8, SAFE_CHUNK_SIZE);
	put_be32(out + 12, SAFE_ARGON_MEM_KIB);
	put_be32(out + 16, SAFE_ARGON_OPS);
	put_be32(out + 20, SAFE_ARGON_THREADS);
	memcpy(out + 24, salt, SAFE_SALT_SIZE);
}

/* check a CREAM header; copy out salt and version */
static inline int
safe_hdr_parse(const uint8_t *buf, uint8_t *salt_out, unsigned *version_out)
{
	static const uint8_t magic[6] = {'C', 'R', 'E', 'A', 'M', '\1'};
	unsigned v;

	if (memcmp(buf, magic, sizeof magic) != 0)
		return -1;
	v = (unsigned)buf[6] << 8 | buf[7];
	if (v != SAFE_FORMAT && v != SAFE_FORMAT_V11)
		return -1;
	if (get_be32(buf + 8) != SAFE_CHUNK_SIZE)
		return -1;
	if (get_be32(buf + 12) != SAFE_ARGON_MEM_KIB)
		return -1;
	if (get_be32(buf + 16) != SAFE_ARGON_OPS)
		return -1;
	if (get_be32(buf + 20) != SAFE_ARGON_THREADS)
		return -1;
	memcpy(salt_out, buf + 24, SAFE_SALT_SIZE);
	if (version_out)
		*version_out = v;
	return 0;
}

#endif
