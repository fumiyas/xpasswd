/* ======================================================================
 *  util.h
 *  Copyright (c) 1997-2002 SATOH Fumiyasu, All rights reserved.
 * ====================================================================== */

#ifndef _UTIL_H_INCLUDED
#define _UTIL_H_INCLUDED

#include <unistd.h>
#include <string.h>

#include "define.h"

int util_read _((int fd,char *buf,size_t bufsize, int msec));
int util_write _((int fd, char *buf, size_t buflen));
char *util_strcpy(char *dst, int dstsize, const char *src);
char *util_strncpy(char *dst, int dstsize, const char *src, int srcmaxlen);
void util_msleep _((int msec));

#ifdef HAVE_STDARG_H
void util_warn _((const char *fmt, /* [arg,] */ ...));
void util_warn_strerr _((const char *fmt, /* [arg,] */ ...));
#else /* HAVE_STDARG_H */
void util_warn _((int va_alist));
void util_warn_strerr _((int va_alist));
#endif /* HAVE_STDARG_H */

#define util_write_string(fd, buf)	util_write(fd, buf, strlen(buf))

#endif /* _UTIL_H_INCLUDED */
