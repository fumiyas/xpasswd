/*
    pty.h
    Copyright (c) 1997-2002 SATOH Fumiyasu, All rights reserved.
*/

#ifndef _PTY_H_INCLUDED
#define _PTY_H_INCLUDED

#include "define.h"

#include <termios.h>
#include <sys/param.h>	/* MAXPATHLEN */

struct pty_info {
    int master;
    int slave;
    char slavename[MAXPATHLEN];
};


RESULT pty_allocate _((struct pty_info *pty));
void   pty_free _((struct pty_info *pty));
RESULT pty_openslave _((struct pty_info *pty));
RESULT pty_makeraw _((int fd));

#if HAVE_CFMAKERAW
#define CFMAKERAW cfmakeraw
#else /* !HAVE_CFMAKERAW */
/* The flags part definition is probably from the linux cfmakeraw man
 * page. We also set the MIN and TIME attributes (note that these use
 * the same fields as VEOF and VEOL). */

#define CFMAKERAW(ios) do {						   \
  (ios)->c_iflag &= ~(IGNBRK|BRKINT|PARMRK|ISTRIP|INLCR|IGNCR|ICRNL|IXON); \
  (ios)->c_oflag &= ~OPOST;						   \
  (ios)->c_lflag &= ~(ECHO|ECHONL|ICANON|ISIG|IEXTEN);			   \
  (ios)->c_cflag &= ~(CSIZE|PARENB); (ios)->c_cflag |= CS8;		   \
  (ios)->c_cc[VMIN] = 1; (ios)->c_cc[VTIME] = 1;			   \
} while(0)
#endif /* !HAVE_CFMAKERAW */

#endif /* _PTY_H_INCLUDED */
