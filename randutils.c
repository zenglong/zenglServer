/*
 * General purpose random utilities
 *
 * Based on libuuid code.
 *
 * This file may be redistributed under the terms of the
 * GNU Lesser General Public License.
 */
#ifndef _GNU_SOURCE
	#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/time.h>

#include <sys/syscall.h>

#include "randutils.h"

static __thread unsigned short ul_jrand_seed[3];

int random_get_fd(void)
{
	int i, fd;
	struct timeval	tv;

	gettimeofday(&tv, 0);
	fd = open("/dev/urandom", O_RDONLY);
	if (fd == -1)
		fd = open("/dev/random", O_RDONLY | O_NONBLOCK);
	if (fd >= 0) {
		i = fcntl(fd, F_GETFD);
		if (i >= 0)
			fcntl(fd, F_SETFD, i | FD_CLOEXEC);
	}
	srandom((getpid() << 16) ^ getuid() ^ tv.tv_sec ^ tv.tv_usec);

	ul_jrand_seed[0] = getpid() ^ (tv.tv_sec & 0xFFFF);
	ul_jrand_seed[1] = getppid() ^ (tv.tv_usec & 0xFFFF);
	ul_jrand_seed[2] = (tv.tv_sec ^ tv.tv_usec) >> 16;

	/* Crank the random number generator a few times */
	gettimeofday(&tv, 0);
	for (i = (tv.tv_sec ^ tv.tv_usec) & 0x1F; i > 0; i--)
		random();
	return fd;
}


/*
 * Generate a stream of random nbytes into buf.
 * Use /dev/urandom if possible, and if not,
 * use glibc pseudo-random functions.
 */
void random_get_bytes(void *buf, size_t nbytes)
{
	size_t i, n = nbytes;
	int fd = random_get_fd();
	int lose_counter = 0;
	unsigned char *cp = (unsigned char *) buf;

	if (fd >= 0) {
		while (n > 0) {
			ssize_t x = read(fd, cp, n);
			if (x <= 0) {
				if (lose_counter++ > 16)
					break;
				continue;
			}
			n -= x;
			cp += x;
			lose_counter = 0;
		}

		close(fd);
	}

	/*
	 * We do this all the time, but this is the only source of
	 * randomness if /dev/random/urandom is out to lunch.
	 */
	for (cp = buf, i = 0; i < nbytes; i++)
		*cp++ ^= (random() >> 7) & 0xFF;


	{
		unsigned short tmp_seed[3];

		memcpy(tmp_seed, ul_jrand_seed, sizeof(tmp_seed));
		ul_jrand_seed[2] = ul_jrand_seed[2] ^ syscall(__NR_gettid);
		for (cp = buf, i = 0; i < nbytes; i++)
			*cp++ ^= (jrand48(tmp_seed) >> 7) & 0xFF;
		memcpy(ul_jrand_seed, tmp_seed,
		       sizeof(ul_jrand_seed)-sizeof(unsigned short));
	}

	return;
}

