
/* hash.c */
#include <stdint.h>

char *get_file_hash(char *fname);
char *get_range_hash(const char *fname, int64_t off, int64_t sz);
const char *get_file_kind(const char *fname);
void hash_set_algorithm(const char *name);
