
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
	error(0, errno, "mmaping `%s'", name);
	close(fd);
	return NULL;
    }
    if (madvise(buf, sz, MADV_SEQUENTIAL))
	error(0, errno, "madvise `%s'", name);

    char *ret = git_blob_digest((const unsigned char *) buf, sz);

    close(fd);

    if (munmap(buf, sz) < 0)
	error(EXIT_FAILURE, errno, "unmapping `%s'", name);

    return ret;
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
