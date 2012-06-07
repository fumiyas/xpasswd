/* ======================================================================
 * util.c: Utility Functions
 * Copyright (c) 1997-2002 SATOH Fumiyasu, All rights reserved.
 *
 * date: 1999-12-15, since 1997-12-14
 * ====================================================================== */

#include "../include/config.h"

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/time.h>

#ifdef HAVE_STDARG_H
# include <stdarg.h>
#else
# include <varargs.h>
#endif

#include "util.h"

/*
 * Global Functions
 * ======================================================================
*/

/*
 * Write data in a single write() system call.
 */
int util_write(fd, buf, buflen)
int fd;
char *buf;
size_t buflen;
{
    return write(fd, buf, buflen);
}

int util_read(fd, buf, bufsize, msec)
int	fd;
char*	buf;
size_t	bufsize;
int	msec;
{
    fd_set		fds;
    struct timeval	timeout;
    int			selret, readret;

    timeout.tv_sec = msec / 1000;
    timeout.tv_usec = (msec % 1000) * 1000;

    FD_ZERO(&fds);
    FD_SET(fd, &fds);
    selret = select(fd+1, &fds, NULL, NULL, (msec > 0) ? &timeout : NULL);
    if (selret == -1) {
	util_warn_strerr("select failed.");
	return -1;
    }
    if (selret == 0) {
	util_warn("timed out while select. (%d msec)", msec);
	return -1;
    }

    readret = read(fd, buf, bufsize);
    if (readret == -1) {
	util_warn_strerr("read failed.");
	return -1;
    }
    if (readret == 0) {
	util_warn("read reached to EOF.");
	return -1;
    }

    return readret;
}

char *util_strcpy(dst, dstsize, src)
char *dst;
const char *src;
int dstsize;
{
    int ncopy = dstsize - 1;

    strncpy(dst, src, ncopy); 
    dst[ncopy] = '\x0';

    return dst;
}

char *util_strncpy(dst, dstsize, src, srcmaxlen)
char *dst;
const char *src;
int dstsize, srcmaxlen;
{
    int ncopy = (srcmaxlen < dstsize) ? srcmaxlen : dstsize - 1;

    strncpy(dst, src, ncopy); 
    dst[ncopy] = '\x0';

    return dst;
}

void util_msleep(int msec)
{
#if HAVE_USLEEP
    if (msec == 0) {
	return;
    }

    usleep(msec * 1000);
#else	/* HAVE_USLEEP */
    struct timeval s;

    if (msec == 0) {
	return;
    }

    s.tv_sec = msec / 1000;
    s.tv_usec = (msec % 1000) * 1000;
    select(0, NULL, NULL, NULL, &s);
#endif	/* HAVE_USLEEP */
}

#ifdef HAVE_STDARG_H
void util_warn(const char *fmt, /* [arg,] */ ...)
#else /* HAVE_STDARG_H */
void util_warn(va_alist)
va_dcl
#endif /* HAVE_STDARG_H */
{
    va_list	vargs;

#ifdef HAVE_STDARG_H
    va_start(vargs, fmt);
#else /* HAVE_STDARG_H */
    char	*fmt;

    va_start(vargs);
    fmt = va_arg(vargs, char *);
#endif /* HAVE_STDARG_H */

    (void)fprintf(stderr, "xpasswd: ");
    (void)vfprintf(stderr, fmt, vargs);
    (void)fprintf(stderr, "\n");
    va_end(vargs);
    fflush(stderr);
}

#ifdef HAVE_STDARG_H
void util_warn_strerr(const char *fmt, /* [arg,] */ ...)
#else /* HAVE_STDARG_H */
void util_warn_strerr(va_alist)
va_dcl
#endif /* HAVE_STDARG_H */
{
    va_list	vargs;

#ifdef HAVE_STDARG_H
    va_start(vargs, fmt);
#else /* HAVE_STDARG_H */
    char	*fmt;

    va_start(vargs);
    fmt = va_arg(vargs, char *);
#endif /* HAVE_STDARG_H */

    (void)fprintf(stderr, "xpasswd: ");
    (void)vfprintf(stderr, fmt, vargs);
    va_end(vargs);
    (void)fprintf(stderr, "%s\n", strerror(errno));
    fflush(stderr);
}

