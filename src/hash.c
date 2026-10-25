
/*
Copyright (C) 2022 Alexios Zavras
SPDX-License-Identifier: LGPL-2.1-or-later
*/

#include "config.h"

#include <errno.h>		       // errno(3)
#include <error.h>		       // error(3)
#include <fcntl.h>		       // open(2)
#include <limits.h>		       // PATH_MAX
#include <stdint.h>		       // uint8_t
#include <stdio.h>		       // sprintf(3)
#include <stdlib.h>		       // realpath(3), exit(3), atoi(3)
#include <string.h>		       // memcmp(3), strcmp(3), strdup(3),
				       // strlen(3)
#include <sysexits.h>		       // EX_OK, EX_NOINPUT, EX_USAGE
#include <sys/mman.h>		       // madvise(2), mmap(2)
#include <sys/stat.h>		       // lstat(2)
#include <sys/sysinfo.h>	       // get_nprocs(3)
#include <sys/types.h>		       // 
#include <unistd.h>		       // optind, readlink(2)

#include <openssl/evp.h>	       // EVP_sha1(), EVP_DigestInit_ex(),
				       // EVP_DigestUpdate(),
				       // EVP_DigestFinal_ex()

#include	"hash.h"

// Digest algorithm for git-blob hashing. Default SHA-1 keeps b:hash values
// git-compatible (upstream / RPM matching); "sha256" selects a collision-
// resistant digest for integrity-grade provenance (threat model, T-hash).
static const EVP_MD *hash_md;

void
hash_set_algorithm(const char *name)
{
    hash_md = (name && !strcmp(name, "sha256")) ? EVP_sha256() : EVP_sha1();
}

static const EVP_MD *
current_md(void)
{
    if (hash_md == NULL)
	hash_md = EVP_sha1();
    return hash_md;
}

static char *
hash_to_str(const unsigned char *h, unsigned int n)
{
    char *hash;
    char *ph;

    ph = hash = malloc(2 * n + 1);
    if (hash == NULL) {
	return NULL;
    }

    for (unsigned int i = 0; i < n; i++) {
#define TO_HEX(i)       "0123456789abcdef"[i]
	*ph++ = TO_HEX(h[i] >> 4);
	*ph++ = TO_HEX(h[i] & 0xF);
    }
    *ph = 0;
    return hash;
}

// git-blob digest of a buffer: hash "blob <sz>\0" then the content, using the
// currently selected algorithm. Returns a malloc'd hex string.
static char *
git_blob_digest(const unsigned char *buf, size_t sz)
{
    char pre[32];
    size_t presize = sprintf(pre, "blob %zu%c", sz, 0);

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();

    EVP_DigestInit_ex(ctx, current_md(), NULL);
    EVP_DigestUpdate(ctx, pre, presize);
    if (sz > 0)
	EVP_DigestUpdate(ctx, buf, sz);
    EVP_DigestFinal_ex(ctx, digest, &dlen);

    EVP_MD_CTX_free(ctx);

    return hash_to_str(digest, dlen);
}

/* Hash a file that cannot be mapped, by reading it.
 *
 * The size reported by stat(2) is a promise only for regular files; for the
 * synthetic ones it is a page-sized placeholder. So the digest covers the bytes
 * actually read, and the git-blob header states that same length, which is what
 * makes the result comparable with a hash of the same content taken anywhere
 * else. Returns NULL if reading fails outright.
 */
static char *
hash_by_reading(int fd, size_t hint)
{
    size_t cap = hint > 0 ? hint : 4096;
    size_t len = 0;
    char *buf = malloc(cap);

    if (buf == NULL)
	return NULL;

    for (;;) {
	if (len == cap) {
	    size_t ncap = cap * 2;
	    char *nbuf = realloc(buf, ncap);

	    if (nbuf == NULL) {
		free(buf);
		return NULL;
	    }
	    buf = nbuf;
	    cap = ncap;
	}
	ssize_t n = read(fd, buf + len, cap - len);

	if (n < 0) {
	    if (errno == EINTR)
		continue;
	    free(buf);
	    return NULL;
	}
	if (n == 0)
	    break;
	len += (size_t) n;
    }

    char *ret = git_blob_digest((const unsigned char *) buf, len);

    free(buf);
    return ret;
}

static char *
hash_file_contents(char *name, size_t sz)
{
    int fd = open(name, O_RDONLY);

    if (fd < 0) {
	error(0, errno, "open `%s'", name);
	return NULL;
    }
    char *buf = mmap(NULL, sz, PROT_READ, MAP_PRIVATE, fd, 0);

    if (buf == MAP_FAILED) {
	// Not everything readable is mappable: sysfs and procfs entries report
	// a size but have no pages behind it. They are ordinary build inputs
	// all the same (the Go runtime reads /sys/.../hpage_pmd_size on every
	// start), so read them instead of dropping them and their hash.
	char *ret = hash_by_reading(fd, sz);

	if (ret == NULL)
	    error(0, errno, "hashing `%s'", name);
	close(fd);
	return ret;
    }
    if (madvise(buf, sz, MADV_SEQUENTIAL))
	error(0, errno, "madvise `%s'", name);

    char *ret = git_blob_digest((const unsigned char *) buf, sz);

    close(fd);

    if (munmap(buf, sz) < 0)
	error(EXIT_FAILURE, errno, "unmapping `%s'", name);

    return ret;
}

/* An ELF file by its e_type: an object file is code a linker copies in, an
 * executable or a shared object is not. */
static const char *
elf_kind(const unsigned char *buf, ssize_t n)
{
    if (n < 18)
	return "elf";

    // e_type is a half-word at offset 16, in the byte order EI_DATA names.
    unsigned type = buf[5] == 2 ? (buf[16] << 8 | buf[17])
	: (buf[17] << 8 | buf[16]);

    switch (type) {
	case 1:
	    return "elf-rel";
	case 2:
	    return "elf-exec";
	case 3:
	    return "elf-dyn";
	default:
	    return "elf";
    }
}

/* What a file's first bytes say it is, for the formats that carry compiled
 * code or pack other files: a .a renamed to .txt, or a library inside a
 * tarball, is no longer told apart by its name.  Returns a static string, or
 * NULL for anything else (text above all). */
const char *
get_file_kind(const char *fname)
{
    static const struct {
	size_t off;
	size_t len;
	const char *magic;
	const char *kind;
    } sigs[] = {
	{0, 4, "\x7f" "ELF", "elf"},	// first: refined by elf_kind()
	{0, 8, "!<arch>\n", "ar"},
	{0, 8, "!<thin>\n", "ar"},
	{0, 4, "\xca\xfe\xba\xbe", "class"},	// also a fat Mach-O
	{0, 4, "\xfe\xed\xfa\xce", "macho"},
	{0, 4, "\xfe\xed\xfa\xcf", "macho"},
	{0, 4, "\xce\xfa\xed\xfe", "macho"},
	{0, 4, "\xcf\xfa\xed\xfe", "macho"},
	{0, 2, "MZ", "pe"},
	{0, 4, "BC\xc0\xde", "bitcode"},
	{0, 4, "\0asm", "wasm"},
	{0, 4, "PK\x03\x04", "zip"},
	{0, 4, "PK\x05\x06", "zip"},
	{0, 2, "\x1f\x8b", "gzip"},
	{0, 6, "\xfd" "7zXZ\0", "xz"},
	{0, 4, "\x28\xb5\x2f\xfd", "zstd"},
	{0, 3, "BZh", "bzip2"},
	{0, 6, "7z\xbc\xaf\x27\x1c", "7z"},
	{0, 4, "\x04\x22\x4d\x18", "lz4"},
	{0, 4, "\xed\xab\xee\xdb", "rpm"},
	{257, 5, "ustar", "tar"},
    };
    unsigned char buf[262];
    int fd = open(fname, O_RDONLY | O_NONBLOCK);

    if (fd < 0)
	return NULL;

    ssize_t n = read(fd, buf, sizeof buf);

    close(fd);
    if (n <= 0)
	return NULL;

    for (size_t i = 0; i < sizeof sigs / sizeof sigs[0]; i++) {
	if ((size_t) n >= sigs[i].off + sigs[i].len
	    && !memcmp(buf + sigs[i].off, sigs[i].magic, sigs[i].len))
	    return i == 0 ? elf_kind(buf, n) : sigs[i].kind;
    }
    return NULL;
}

char *
get_file_hash(char *fname)
{
    struct stat fstat;

    if (stat(fname, &fstat)) {
	error(0, errno, "getting info on `%s'", fname);
	return NULL;
    }
    if (S_ISREG(fstat.st_mode) || S_ISLNK(fstat.st_mode)) {
	size_t sz = fstat.st_size;

	if (sz > 0)
	    return hash_file_contents(fname, sz);
	return git_blob_digest(NULL, 0);   // empty-file git-blob hash
    }
    return NULL;
}
