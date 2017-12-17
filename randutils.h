#ifndef UTIL_LINUX_RANDUTILS
#define UTIL_LINUX_RANDUTILS

#include <stddef.h>

extern int random_get_fd(void);
extern void random_get_bytes(void *buf, size_t nbytes);

#endif
