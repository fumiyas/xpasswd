/* ======================================================================
 * chpasswd.c: Change password by /usr/bin/passwd
 * Copyright (c) 1997-2002 SATOH Fumiyasu, All rights reserved.
 *
 * date: 1999-12-13, since 1997-05-23
 * reference sources:
 *	poppassd 1.4		(poppassd.c from POPPasswd.tar.gz)
 *	poppassd-freebsd 1.2	(poppassd.c from poppassd-freebsd.tar.gz)
 *	samba 2.0.6		(chgpasswd.c from samba-2.0.6.tar.gz)
 * ====================================================================== */

#include "../include/config.h"

#define BUFSIZE 512

#include <stdio.h>
#include <unistd.h>
#include <ctype.h>
#include <pwd.h>
#include <grp.h>
#include <sys/wait.h>
#include <sys/time.h>

#include "xpasswd.h"
#include "pty.h"
#include "util.h"
#include "chpasswd.h"

/* global value */
static char ear[BUFSIZE];

/* static functions */
static RESULT _chpass_parent _((int fd,char *user,char *pass,char *newpass));
static RESULT _chpass_child _((struct pty_info *pty, char *user));
static BOOL _chpass_match _((char *str,char *regexp, BOOL case_sig));
static BOOL _chpass_expect _((int fd, char *issue,char **expect,char *buf,int bufsize));

/* ====================================================================== */

/* Prompt strings expected from the "passwd" command. If you want
 * to port this program to yet another flavor of UNIX, you may need to add
 * more prompt strings here.
 *
 * Each prompt is defined as an array of pointers to alternate 
 * strings, terminated by an empty string. In the strings, '*'
 * matches any sequence of 0 or more characters. Pattern matching
 * is case-insensitive.
 */

/* System			passwd database			*/
/* ---------------------------	-------------------------	*/
/* Solaris 2.5.1		/etc/passwd, NIS, NIS+		*/
/* SunOS 4.1.3-JL		NIS				*/
/* BSD/OS 2.0.1			/etc/passwd, NIS		*/
/* Linux 2.0.31 (Slackware 3.x)	/etc/passwd			*/
/* Linux 2.0.3x (Red Hat 5.2)	/etc/passwd			*/
/* FreeBSD 2.2.5-RELEASE	/etc/passwd			*/
/* FreeBSD 3.1-RELEASE		/etc/passwd			*/
/* HP-UX 10.20			/etc/passwd                     */
/* IRIX 6.4			/etc/passwd, NIS                */
/* NetBSD 1.3.2			/etc/passwd, NIS		*/

#ifdef CIJ
static char *PN[] = {
    "Please enter your old Secure RPC password: ",	/* Solaris 2.6 */
    NULL
};
#endif	/* CIJ */

/*
 * Generic UNIX
 * ----------------------------------------------------------------------
 */
#define PASSWD_WANT_USERNAME 1

/*
 * Solaris 2.x
 * ----------------------------------------------------------------------
 */
#if SYS_SOLARIS
static char *P1[] = {
    "Enter existing login ?assword: ",	/* Solaris 8 2/02 */
    "Enter login ?assword: ",		/* Solaris 2.5.1, 2.6, 8 */
    "Enter login(NIS) password: ",	/* Solaris 2.5.1 */
    "Enter login(NIS+) password: ",	/* Solaris 2.5.1 */
    "Old password: ",			/* Solaris 2.4 */
    NULL
};
static char *P2[] = {
    "\nNew ?assword: ",			/* Solaris 2.6, 8  */
    "\nNew password:",			/* Solaris 2.4, 2.5.1 */
    NULL
};
static char *P3[] = {
    "\nRe-enter new ?assword: ",	/* Solaris 2.6, 8 */
    "\nRe-enter new password:",		/* Solaris 2.5.1 */
    "\nRe-enter new  password:",	/* Solaris 2.4 */
    NULL
};
static char *P4[] = {
    /* Solaris 8 2/02 */
    "passwd: password successfully changed for *\n",
    /* Solaris 2.6, 8 */
    "passwd (SYSTEM): passwd successfully changed for *\n",
    /* Solaris 2.5.1 */
    "NIS(YP) passwd/attributes changed on *",
    "\n        NIS+ password information changed for *\n",

    NULL
};
#endif /* SYS_SOLARIS */

/*
 * SunOS 4.x
 * ----------------------------------------------------------------------
*/
#if SYS_SUNOS
static char *P1[] = {
    "Changing password for * on *.\nOld password:",
    "Changing NIS password for * on *.\nOld password:",
    NULL
};
static char *P2[] = {
    "\nNew password:",
    NULL
};
static char *P3[] = {
    "\nRetype new password:",
    NULL
};
static char *P4[] = {
    "NIS entry changed on *\n",
    "\n",
    NULL
};
#endif /* SYS_SUNOS */

/*
 * BSD/OS 2.x
 * FreeBSD 2.1R
 * NetBSD 1.3.2
 * ----------------------------------------------------------------------
 */
#if SYS_BSDI || SYS_FREEBSD || SYS_NETBSD
#if SYS_BSDI
#undef PASSWD_WANT_USERNAME
#endif /* SYS_BSDI */
static char *P1[] = {
    "Changing local password for *.\nOld password:",	/* BSD/OS 2.x */
							/* FreeBSD 2.2.5-RELEASE */
							/* NetBSD 1.3.2 */
    "Old password:",
    "Changing password for *.\nOld password:",
    "Changing password for * on *.\nOld password:",
    "Changing NIS password for * on *.\nOld password:",
    "Changing password for *\n*'s Old password:",
    "Changing YP password for *.\nOld password:",	/* NetBSD 1.3.2 */
    NULL
};
static char *P2[] = {
    "\nNew password:",					/* BSD/OS 2.0 */
							/* FreeBSD 2.2.5-RELEASE */
							/* NetBSD 1.3.2 */
    "\nNew password (8 significant characters):",	/* BSD/OS 2.1 */
    "\n*'s New password:",
    NULL
};
static char *P3[] = {
    "\nRetype new password:",				/* BSD/OS 2.x */
							/* FreeBSD 2.2.5-RELEASE */
							/* NetBSD 1.3.2 */
    "\nRe-enter new password:",
    "\nEnter the new password again:",
    "\n*Re-enter *'s new password:",
    "\nVerify:",
    NULL
};
static char *P4[] = {
    "\npasswd: updating passwd database\npasswd: done\n",/* BSD/OS 2.x */
    "\npasswd: updating the database...\npasswd: done\n",/* FreeBSD 2.2.5-RELEASE */
    "\n",						 /* NetBSD 1.3.2 */
    NULL
};
#endif /* SYS_BSDI || SYS_FREEBSD || SYS_NETBSD */

/*
 * Linux (Red Hat, Slackware, etc.)
 * ----------------------------------------------------------------------
*/
#if SYS_LINUX
#undef PASSWD_WANT_USERNAME
static char *P1[] = {
    "Changing password for *\n* password: ",		/* Red Hat Linux 5.2 */
    "Changing password for *\nOld password:",		/* Slackware 3.4 */
    "Changing password for *\nEnter old password: ",	/* Slackware 3.1 */
    "Password: ",					/* Slackware 2.x? */
    NULL
};
static char *P2[] = {
    "\nNew * password: ",				/* Red Hat Linux 5.2 */
    "*\nNew password:",					/* Slackware 3.4 */
    "\nEnter new password: ",
    "\r\nEnter new password: ",
    "\nNew password: ",					/* Slackware 2.x? */
    NULL
};
static char *P3[] = {
    "\nRetype new * password: ",			/* Red Hat Linux 5.2 */
    "\nRe-enter new password:",				/* Slackware 3.4 */
    "\nRe-type new password: ",
    "\r\nRe-type new password: ",
    "\nNew password (again): ",				/* Slackware 2.x? */
    NULL
};
static char *P4[] = {
    "\n*successfully*",					/* Red Hat Linux 5.2 */
    "*Password changed*",				/* Slackware 3.4 */
    "\r\nPassword changed.\n",
    "\n",
    NULL
};
#endif /* SYS_LINUX */

/*
 * HPUX
 * ----------------------------------------------------------------------
*/
#if SYS_HPUX
static char *P1[] = {
    "Old password:",					/* HPUX 10.20 */
    NULL
};
static char *P2[] = {
    "\nNew password:",					/* HPUX 10.20 */
    NULL
};
static char *P3[] = {
    "\nRe-enter new password:",				/* HPUX 10.20 */
    NULL
};
static char *P4[] = {
    "\n",
    NULL
};
#endif /* SYS_HPUX */

/*
 * IRIX
 * ----------------------------------------------------------------------
*/
#if SYS_IRIX
static char *P1[] = {
    "Old password:",					/* IRIX 6.4 */
    "Changing NIS password *\nOld password:",		/* IRIX 6.4 */
    NULL
};
static char *P2[] = {
    "\nNew password:",					/* IRIX 6.4 */
    NULL
};
static char *P3[] = {
    "\nRe-enter new password:",				/* IRIX 6.4 */
    "\nRetype new password:",				/* IRIX 6.4 */
    NULL
};
static char *P4[] = {
    "\n",
    NULL
};
#endif /* SYS_IRIX */

/*
 * Global Functions
 * ======================================================================
*/

RESULT ChangePasswd(username, pass_old, pass_new)
char *username, *pass_old, *pass_new;
{
    struct pty_info pty;
    pid_t pid, wpid;
    int	  wstat;

    if (!IsSuitablePasswd(username, pass_new, pass_old)) {
	util_warn("new passwd is not complex.");
	return FAILURE;
    }

    /* get pty to talk to password program */
    if (pty_allocate(&pty) == FAILURE) {
	util_warn("cannot allocate pty.");
	return FAILURE;
    }

    /* fork child process to talk to password program */
    if ((pid = fork()) < 0) {
	util_warn_strerr("cannot fork child for %s.", PASSWD_EXE);
	pty_free(&pty);
	return FAILURE;
    }

    if (pid > 0) { /* Parent */
	if (_chpass_parent(pty.master, username, pass_old, pass_new) == FAILURE) {
	    util_warn("failed attempt by %s.", username);
	    util_warn("cannot change password.\n" );
	    return FAILURE;
	}

	util_warn("waiting for child %s. (pid %d)", PASSWD_EXE, pid);
	if ((wpid = waitpid(pid, &wstat, 0)) < 0) {
	    util_warn_strerr("wait faild for %s.", PASSWD_EXE);
	    pty_free(&pty);
	    return FAILURE;
	}

	pty_free(&pty);

	if (wpid != pid) {
	    util_warn("wrong child (not %s) waiting for!", PASSWD_EXE);
	    return FAILURE;
	}

	if (WIFEXITED(wstat) == 0) {
	    util_warn("child %s killed? (%d)", PASSWD_EXE, wstat);
	    return FAILURE;
	}

	if (WEXITSTATUS(wstat) != 0) {
	    util_warn("child %s exited abnormally. (%d)", PASSWD_EXE, wstat);
	    return FAILURE;
	}
	util_warn("child %s returned %d.", PASSWD_EXE, WEXITSTATUS(wstat));

	util_warn("password changed for %s.", username);

	return SUCCESS;
    } else {    /* Child passwd */
	/*
	 * Become the user trying who's password is being changed.  We're
	 * about to exec /usr/bin/passwd with is setuid root anyway, but this
	 * way it looks to the child completely like it's being run by
	 * the normal user, which makes it do its own password verification
	 * before doing any thing.  In theory, we've already verified the
	 * password, but this extra level of checking doesn't hurt.  Besides,
	 * the way I do it here, if somebody manages to change somebody
	 * else's password, you can complain to your vendor about security
	 * holes, not to me!
	 */

	_chpass_child(&pty, username);

	/* if _chpass_child is returned ... */
	util_warn("cannot do child %s.", PASSWD_EXE);
	exit(1);
    }
}

/* Suitable (complex) passwd ? */
BOOL IsSuitablePasswd(user, pass_new, pass_old)
char *user, *pass_new, *pass_old;
{
    int		i;
    int		user_len;
    int		pass_new_len, pass_old_len;
    int		alpha_num, pass_new_gap;

    user_len      = strlen(user);
    pass_new_len  = strlen(pass_new);
    pass_old_len  = strlen(pass_old);

    /* check length */
    if (pass_new_len < PASSWD_LEN_MIN) {
	util_warn("new passwd is too short.");
	return FALSE;
    }

    /* check elements */
    for (i = alpha_num = 0; i < pass_new_len; i++) {
	alpha_num += isalpha(pass_new[i]) ? 1 : 0;
    }
    if ((alpha_num < PASSWD_ELEM_ALPHA) ||
	(pass_new_len - alpha_num < PASSWD_ELEM_OTHER)) {
	util_warn("new password element is not enough.");
	return FALSE;
    }

    /* user appeared in new passwd? */
    if (user_len == pass_new_len) {
	char user2[MAXIN], pass_new2[MAXIN * 2];
	int user2_len = user_len;
	int pass_new2_len = pass_new_len * 2;

	/* in order */
	strcpy(user2, user);
	strcpy(pass_new2, pass_new);
	strcat(pass_new2, pass_new);
	for (i = 0; i < user2_len; i++) {
	    user2[i] = tolower(user2[i]);
	}
	for (i = 0; i < pass_new2_len; i++) {
	    pass_new2[i] = tolower(pass_new2[i]);
	}
	if (strstr(pass_new2, user2) != NULL) {
	    util_warn("username appeared in new passwd.");
	    return FALSE;
	}

	/* in reverse */
	for (i = 0; i < user_len; i++) {
	    user2[i] = tolower(user[user_len - i - 1]);
	}
	user2[i] = '\0';	/* not needed, but for clearly */
	if (strstr(pass_new2, user2) != NULL) {
	    util_warn("username appeared in new passwd.");
	    return FALSE;
	}
    }

    /* check gap of old/new passwd */
    for (i = pass_new_gap = 0; (i < pass_new_len) && (i < pass_old_len); i++) {
	pass_new_gap += (tolower(pass_new[i]) != tolower(pass_old[i])) ? 1 : 0;
    }
    pass_new_gap += abs(pass_new_len - pass_old_len);
    if (pass_new_gap < PASSWD_LEN_DIFF) {
	util_warn("gap between old/new passwd is not enough.");
	return FALSE;
    }

    return TRUE;
}

/* Local (static) Functions
 * ====================================================================== */

/*
 * _chpass_parent()
 *
 * Handles the conversation between the parent and child (password program)
 * processes.
 *
 * Returns SUCCESS is the conversation is completed without any problems,
 * FAILURE if any errors are encountered (in which case, it can be assumed
 * that the password wasn't changed).
 */
static RESULT _chpass_parent(fd, user, pass_old, pass_new)
int fd;
char *user, *pass_old, *pass_new;
{
    char mouth[BUFSIZE];

    util_warn("waiting for expected string (P1) from %s.", PASSWD_EXE);
    if (_chpass_expect(fd, NULL, P1, ear, sizeof(ear)) == FALSE) {
	util_warn("unexpected string (P1) from %s.", PASSWD_EXE);
	return FAILURE;
    }

    util_strcpy(mouth, sizeof(mouth), pass_old);
#ifdef CIJ
    if (opt_N) {
	if (_chpass_expect(fd, mouth, PN, ear, sizeof(ear)) == FALSE) {
	    util_warn("unexpected string (PN) from %s.", PASSWD_EXE);
	    return FAILURE;
	}
	/* Default secure password is `nisplus`. */
	util_strcpy(mouth, sizeof(mouth), "nisplus");
    }
#endif	/* CIJ */
    util_warn("waiting for expected string (P2) from %s.", PASSWD_EXE);
    if (_chpass_expect(fd, mouth, P2, ear, sizeof(ear)) == FALSE) {
	util_warn("unexpected string (P2) from %s.", PASSWD_EXE);
	return FAILURE;
    }

    util_strcpy(mouth, sizeof(mouth), pass_new);
    util_warn("waiting for expected string (P3) from %s.", PASSWD_EXE);
    if (_chpass_expect(fd, mouth, P3, ear, sizeof(ear)) == FALSE) {
	util_warn("unexpected string (P3) from %s.", PASSWD_EXE);
	return FAILURE;
    }
    util_warn("waiting for expected string (P4) from %s.", PASSWD_EXE);
    if (_chpass_expect(fd, mouth, P4, ear, sizeof(ear)) == FALSE) {
	util_warn("unexpected string (P4) from %s.", PASSWD_EXE);
	return FAILURE;
    }

    return SUCCESS;
}

/*
 * _chpass_child
 *
 * Do child stuff - set up slave pty and execl /usr/bin/passwd.
 *
 * Code adapted from "Advanced Programming in the UNIX Environment"
 * by W. Richard Stevens.
 *
 */
static RESULT _chpass_child(pty, user)
struct pty_info *pty;
char *user;
{
    struct passwd *pw;

    pw = getpwnam(user);
    if (pw == NULL) {
	util_warn("user %s doesn't exist in password database.", user);
	return FAILURE;
    }

    /* Start new session - gets rid of controlling terminal. */
    if (setsid() < 0) {
	util_warn_strerr("setsid failed.");
	util_warn("cannot start new session.");
	return FAILURE;
    }

    /* Open slave pty and acquire as new controlling terminal. */
    if (pty_openslave(pty) == FAILURE) {
	util_warn_strerr("open failed.");
	util_warn("cannot open slave pty%s", pty->slavename);
	pty_free(pty);
	return FAILURE;
    }

    /* Make slave stdin/out/err of child. */
    if (dup2(pty->slave, STDIN_FILENO) != STDIN_FILENO) {
	util_warn_strerr("cannot duplicate slave pty into STDIN");
	pty_free(pty);
	return FAILURE;
    }
    if (dup2(pty->slave, STDOUT_FILENO) != STDOUT_FILENO) {
	util_warn_strerr("cannot duplicate slave pty into STDOUT");
	pty_free(pty);
	return FAILURE;
    }
    if (dup2(pty->slave, STDERR_FILENO) != STDERR_FILENO) {
	util_warn_strerr("cannot duplicate slave pty into STDERR");
	pty_free(pty);
	return FAILURE;
    }
    pty_free(pty);

    if (pty_makeraw(STDIN_FILENO) == FAILURE) {
	util_warn("cannot make slave pty to raw mode.");
	return FAILURE;
    }

    /* change real and effective group-id */
    if (setgid(pw->pw_gid)) {
	util_warn_strerr("setgid failed.");
	util_warn("cannot set GID.");
	return FAILURE;
    }
#if HAVE_INITGROUPS
    /* initialize groups */
    if (initgroups(pw->pw_name, pw->pw_gid)) {
	util_warn_strerr("initgroups failed.");
	util_warn("cannot initialize GID.");
	return FAILURE;
    }
#endif /* HAVE_INITGROUPS */

    /* change real and effective user-id */
    if (setuid(pw->pw_uid)) {
	util_warn_strerr("setuid failed.");
	util_warn("cannot set UID.");
	return FAILURE;
    }

    putenv("LC_ALL=C");

    /* Exec /usr/bin/passwd. */
#if PASSWD_WANT_USERNAME
    if (execl(PASSWD_EXE, PASSWD_EXE, user, NULL) < 0)
#else /* PASSWD_WANT_USERNAME */
    if (execl(PASSWD_EXE, PASSWD_EXE, NULL) < 0)
#endif /* PASSWD_WANT_USERNAME */
    {
	util_warn_strerr("execl failed.");
	util_warn("cannot exec %s.", PASSWD_EXE);
	return FAILURE;
    }

    return SUCCESS;	/* dummy */
}

static BOOL _chpass_match(str, regexp, case_sig)
char *str, *regexp;
BOOL case_sig;
{
    char *p;

    for (p = regexp; *p && *str; ) {
	switch (*p) {
	case '?':
	    str++; p++;
	    break;

	case '*': /* Look for a character matching the one after the '*' */
	    p++;
	    if (!*p) {
		return TRUE; /* Automatic match */
	    }
	    while (*str) {
		while (*str && (case_sig ? (*p != *str) : (toupper(*p)!=toupper(*str))))
		    str++;
		if (_chpass_match(str, p, case_sig))
		    return TRUE;
		if (!*str)
		    return FALSE;
		else
		    str++;
	    }
	    return FALSE;

	default:
	    if(case_sig) {
		if(*str != *p)
		    return FALSE;
	    } else {
		if(toupper(*str) != toupper(*p))
		    return FALSE;
	    }
	    str++, p++;
	    break;
	}
    }

    if(!*p && !*str)
	return TRUE;

    if (!*p && str[0] == '.' && str[1] == 0)
	return(TRUE);
  
    if (!*str && *p == '?') {
	while (*p == '?') p++;
	return(!*p);
    }

    if(!*str && (*p == '*' && p[1] == '\0'))
	return TRUE;

    return FALSE;
}

static BOOL _chpass_expect(fd, issue, expected, buf, bufsize)
int	fd;
char	*issue;
char	**expected;
char	*buf;
int	bufsize;
{
    int attempt, timeout, nread, len;
    char **s;
    BOOL match;

    /* This loop is for preventing from occuring dead-locking. */
    for (attempt = 0; attempt < PASSWD_RETRY; attempt++) {
	if (issue != NULL) {
	    /* The passwd(1) calls getpass(3) function to read password
	     * from client. In this function, tcsetattr(3) function is
	     * called with TCSAFLUSH action that discard received data.
	     * The following waiting helps to prevent from dead-locking.
	     * But this is not perfect... :-( */
	    util_msleep(100);
	    util_write_string(fd, issue);
	    util_write_string(fd, "\n");
	}

	timeout = PASSWD_TIMEOUT;
	nread = 0;
	buf[0] = 0;
	match = FALSE;
	while ((len = util_read(fd, buf+nread, bufsize-nread-1, timeout)) > 0) {
	    nread += len;
	    buf[nread] = 0;
	    util_warn("%s said: '%s'", PASSWD_EXE, buf);
	    for (s = expected; *s != NULL && !match; s++) {
		if ((match = _chpass_match(buf, *s, FALSE)) == TRUE) {
		    timeout /= 10;
		}
	    }
	}
	if (match) {
	    return TRUE;
	}
	if (len < 0) {
	    util_warn("cannot get expected string from %s.", PASSWD_EXE);
	    return FALSE;
	}
    }

    return match;	/* prevent from warning message by compiler */
}

