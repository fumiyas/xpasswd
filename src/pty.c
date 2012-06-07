/* ======================================================================
 * pty.c: pseudo-terminal (aka pty) library
 * Copyright (c) 1997-2002 SATOH Fumiyasu, All rights reserved.
 * 1999-12-15, since 1999/09/07
 * ====================================================================== */

#include "../include/config.h"

#include <fcntl.h>
#include <string.h>
#include <sys/ioctl.h>

#if HAVE_DEV_PTMX
#include <stdlib.h>
#include <unistd.h>
#include <sys/stropts.h>
#else /* HAVE_DEV_PTMX */
#include <dirent.h>
#endif /* HAVE_DEV_PTMX */

#include "pty.h"

static void _pty_clear(pty)
struct pty_info *pty;
{
    pty->master = pty->slave = -1;
    pty->slavename[0] = '\0';
}

RESULT pty_allocate(pty)
struct pty_info *pty;
{
#if HAVE_DEV_PTMX
    /*
     * Refer to:
     *     UNIX(R) NETWORK PROGRAMMING by W. Richard Stevens
     *     GNU LSH 0.1.9, server_pty.c
     */

    char *slavename;

    _pty_clear(pty);

    if ((pty->master = open("/dev/ptmx", O_RDWR)) < 0) {
	util_warn_strerr("cannot open /dev/ptmx for master pty.");
	return FAILURE;
    }
    if (grantpt(pty->master) < 0) {
	util_warn_strerr("cannot grant access to slave pty.");
	close(pty->master);
	return FAILURE;
    }
    if (unlockpt(pty->master) < 0) {
	util_warn_strerr("cannot unlock master/slave pty pair.");
	close(pty->master);
	return FAILURE;
    }

    if ((slavename = ptsname(pty->master)) == NULL) {
	util_warn("cannot get name of slave pty.");
	close(pty->master);
	return FAILURE;
    }
    strcpy(pty->slavename, slavename);
    util_warn("slave pty device is %s.", pty->slavename);

    return SUCCESS;

#else /* HAVE_DEV_PTMX */
    DIR *dirp;
    struct dirent *dp;
    char mastername[MAXPATHLEN];

    _pty_clear(pty);

    dirp = opendir("/dev");
    if (dirp == NULL) {
	util_warn_strerr("cannot open directory /dev.");
	return FAILURE;
    }

    while ((dp = readdir(dirp)) != NULL) {
	if (strncmp(dp->d_name, "pty", 3) != 0 || strlen(dp->d_name) != 5) {
	    continue;
	}

	strcpy(mastername, "/dev/");
	strcat(mastername, dp->d_name);

	util_warn("try to open %s for master pty.", mastername);
	if ((pty->master = open(mastername, O_RDWR)) < 0) {
	    continue;
	}
	util_warn("master pty device is %s.", mastername);

	strcpy(pty->slavename, mastername);
	pty->slavename[5] = 't';
	util_warn("slave pty device is %s.", pty->slavename);
	break;
    }
    closedir(dirp);

    if (pty->master < 0) {
	util_warn_strerr("cannot find master pty.");
	return FAILURE;
    }

    return SUCCESS;
#endif /* HAVE_DEV_PTMX */
}

void pty_free(pty)
struct pty_info *pty;
{
    if (pty->master >= 0) {
	close(pty->master);
    }
    if (pty->slave >= 0) {
	close(pty->slave);
    }

    _pty_clear(pty);
}

/*
 * Open slave pty device and set attributes
 */
RESULT pty_openslave(pty)
struct pty_info *pty;
{
    if ((pty->slave = open(pty->slavename, O_RDWR)) < 0) {
	util_warn_strerr("cannot open %s for slave pty.", pty->slavename);
	return FAILURE;
    }

#if HAVE_DEV_PTMX
    if (ioctl(pty->slave, I_PUSH, "ptem") < 0 || ioctl(pty->slave, I_PUSH, "ldterm")) {
	util_warn_strerr("cannot push slave pty for modules.");
	return FAILURE;
    }
#else /* HAVE_DEV_PTMX */
    if (ioctl(pty->slave, TIOCSCTTY, NULL) < 0) {
	util_warn_strerr("cannot make slave pty for controlling terminal.");
	return FAILURE;
    }
#endif /* HAVE_DEV_PTMX */

    return SUCCESS;
}

RESULT pty_makeraw(fd)
int fd;
{
    struct termios ios;

    if (tcgetattr(fd, &ios) < 0) {
	util_warn_strerr("cannot get attributes of fd.");
	return FAILURE;
    }
#if 1
    CFMAKERAW(&ios);
#else /* 1 */
    ios.c_lflag &= ~(ECHO | ECHOE | ECHOK | ECHONL);
    ios.c_lflag |= ICANON;
    ios.c_oflag &= ~(ONLCR);
#endif /* 1 */
    if (tcsetattr(fd, TCSADRAIN, &ios) < 0) {
	util_warn_strerr("cannot set attributes of fd.");
	return FAILURE;
    }

    return SUCCESS;
}
