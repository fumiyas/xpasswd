/* ======================================================================
 *  Authenticate user/passwd
 *  Copyright (c) 1997-2002 SATOH Fumiyasu, All rights reserved.
 *  date: 1998-08-05, since 1997-05-23
 * ====================================================================== */

#include "../include/config.h"

#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>

#ifdef HAVE_ETC_SHADOW
#ifdef HAVE_SHADOW_H
#include <shadow.h>
#endif /* HAVE_SHADOW_H */
#endif /* HAVE_ETC_SHADOW */

#ifdef HAVE_CRYPT_H
#include <crypt.h>
#endif /* HAVE_CRYPT_H */

#include "authuser.h"

/* user/passwd is correct ? */
RESULT AuthenticateUser(user_in, passwd_in)
char *user_in, *passwd_in;
{
    char	*passwd_crypt, *passwd;
    int		passwd_diff;
#ifdef HAVE_ETC_SHADOW
    struct spwd	*shadow_pwd;
#else /* HAVE_ETC_SHADOW */
    struct passwd *normal_pwd;
#endif /* HAVE_ETC_SHADOW */

    /* get user entry */
#ifdef HAVE_ETC_SHADOW
    if (geteuid() != 0) {
	util_warn("permission denied. (super-user only)");
	return FAILURE;
    }
    shadow_pwd = getspnam(user_in);
    if (shadow_pwd == NULL) {
	util_warn("unable to get shadow password entry for %s.", user_in);
	return FAILURE;
    }
    passwd = shadow_pwd->sp_pwdp;
#else /* HAVE_ETC_SHADOW */
    normal_pwd = getpwnam(user_in);
    if (normal_pwd == NULL) {
	util_warn("unable to get password entry for %s.", user_in);
	return FAILURE;
    }
    passwd = normal_pwd->pw_passwd;
#endif /* HAVE_ETC_SHADOW */

    /* check passwd */
    passwd_crypt = crypt(passwd_in, passwd);
    passwd_diff = strcmp(passwd, passwd_crypt);
#if 0
    util_warn("[%s][%s][%s][%s]", user_in, passwd_in, passwd, passwd_crypt);
    util_warn("[%d]", passwd_diff);
#endif /* 0 */

    return (passwd_diff == 0) ? SUCCESS : FAILURE;
}

