/*
    xpasswd - non-interactive passwd command
    Copyright (c) 1997-2004 SATOH Fumiyasu, All rights reserved.

    date: 2004-06-07, since 1997-05-23
*/

#ifdef HAVE_CONFIG_H
#include "../include/config.h"
#endif /* HAVE_CONFIG_H */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pwd.h>
#include <grp.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "util.h"
#include "authuser.h"
#include "chpasswd.h"

#include "xpasswd.h"

static char COPY[] = PACKAGE_COPYRIGHT;
static char VER[] =  PACKAGE_VERSION;

/* functions */
int main _((int argc, char **argv));
/* static functions */
static char *ReadValue _((char *buf, int len));
static void TruncateString _((char *str, int len));

/* options */
int	opt_a=0, opt_s=0, opt_d=0, opt_p=0;
char	*opt_c = NULL;

int main(int argc, char **argv)
{
    int		i;
    extern int	getopt _((int, char * const *, const char *));
    extern char	*optarg;
    int		opt;
    struct passwd *pw;
    char	user_buf[MAXIN], pass_buf[MAXIN], newpass_buf[MAXIN];
    char	*username, *pass_old, *pass_new;

    /* paranoia? */
    argc = (argc < MAXARGC) ? argc : MAXARGC;
    for (i=0; i<argc; i++) {
	TruncateString(argv[i], MAXARGVLEN);
    }

    /* parsing opitons */
    while ((opt = getopt(argc, argv, "asdc:pqh")) != EOF)
    {
	switch (opt) {
	    case 'a':	/* authentication only */
		opt_a = 1;
		break;
	    case 's':	/* check shell */
		opt_s = 1;
		break;
	    case 'd':	/* check home directory */
		opt_d = 1;
		break;
	    case 'c':	/* execute command by user*/
		opt_c = optarg;
		break;
	    case 'p':	/* protocol mode */
		opt_p = 1;
		break;
	    case 'q':	/* this is obsolete option */
		break;
	    case 'h':	/* show help message */
		puts("xpasswd - non-interactive passwd command");
		puts(COPY);
		printf("version %s\n\n", VER);
		puts("usage:");
		puts("\txpasswd [-a|-c command] [-sdp] [-v[v[v]]]");
		puts("options:");
		puts("\t-a\t\tauthentication only");
		puts("\t-c command\texecute command by authenticated user");
		puts("\t-s\t\tcheck if user's shell is valid (not implemented yet)");
		puts("\t-d\t\tcheck if user's home directory exists");
#if 0
		puts("\t-p\t\tprotocol mode");
#endif
		puts("\t-v\t\tverbose output to stderr");
		puts("\t-h\t\tshow this message");
		puts("return values:");
		puts("\t  0\t\tsuccess");
		puts("\t  1\t\tinvalid option");
		/*puts("\t  2\t\permission denied");*/
		puts("\t100\t\tusername is not passed");
		puts("\t101\t\tpassword is not passed");
		puts("\t102\t\tnew password is not passed");
		puts("\t110\t\tuser does not exist");
		puts("\t111\t\tpassword is incorrect");
		puts("\t112\t\tuser's shell is invalid");
		puts("\t113\t\tuser's home directory does not exist");
		puts("\t120\t\tcannot change uid");
		puts("\t121\t\tcannot change gid");
		puts("\t122\t\tcannot initialize gid");
		puts("\t123\t\tcannot execute command");
		puts("\t130\t\tnew password is not suitable string");
		puts("\t139\t\tcannot change password via passwd command");
		exit(0);
	    default:	/* show usage */
		puts("xpasswd [-a|-c command] [-sdpq] [-v[v[v]]]");
		puts("xpasswd -h");
		exit(1);
	}
    }
    if (opt_a && opt_c) {
	puts("xpasswd [-a|-c command] [-dpq] [-v...]");
	exit(1);
    }

    /* non-buffered */
    setbuf(stdout, NULL);

    /* get user and passwd */
    util_write_string(200, "I'm xpasswd. Who are you?");
    username = ReadValue(user_buf, sizeof(user_buf));
    if ((username == NULL) || (strlen(username) == 0)) {
	util_warn("username is not passed.");
	util_write_string(500, "Username required.");
	exit(100);
    }

    util_write_string(300, "Please send your password now.");
    pass_old = ReadValue(pass_buf, sizeof(pass_buf));
    if (pass_old == NULL) {
	util_warn("password is not passed.");
	util_write_string(501, "Password required.");
	exit(101);
    }

    /* authenticate */
    /*----------------------------------------------------------------------*/

    /* get user entry */
    pw = getpwnam(username);
    if (pw == NULL) {
	util_warn("unalbe to get password entry for %s.", username);
	util_write_string(510, "User does not exist in passwd database.");
	exit(110);
    }

#ifdef HAVE_GETUSERSHELL
    /* check shell */
    if (opt_s) {
	extern char *getusershell _((void));
	extern void setusershell _((void));
	extern void endusershell _((void));
	char *shell;
	int valid = 0;

	setusershell();
	while ((shell = getusershell()) != NULL) {
	    if (!strcmp(pw->pw_shell, shell)) {
		valid = 1;
		break;
	    }
	}
	endusershell();
	if (!valid) {
	    util_warn("%s's shell is invalid.", username);
	    util_write_string(512, "User's shell is invalid.");
	    exit(112);
	}
    }
#endif /* HAVE_GETUSERSHELL */

    /* check home directory */
    if (opt_d) {
	struct stat dir_stat;

	if ((stat(pw->pw_dir, &dir_stat) == -1) || !(dir_stat.st_mode & S_IFDIR)) {
	    util_warn("%s's home directory does not exist.", username);
	    util_write_string(513, "User's home directory does not exist.");
	    exit(113);
	}
    }

    /* check username/passwd */
    if (AuthenticateUser(username, pass_old) != SUCCESS) {
	util_warn("username or password is incorrect.");
	util_write_string(511, "Password is incorrect.");
	exit(111);
    }

    /* authentication only */
    /*----------------------------------------------------------------------*/
    if (opt_a) {
	util_write_string(210, "OK. You are trusted user.");
	exit(0);
    }

    /* execute command */
    /*----------------------------------------------------------------------*/
    if (opt_c) {

#ifdef HAVE_INITGROUPS
	/* initialize groups */
	if (initgroups(pw->pw_name, pw->pw_gid)) {
	    util_warn_strerr("cannot initialize GID.");
	    util_write_string(522, "Oops! Cannnot initialize GID.");
	    exit(122);
	}
#endif /* HAVE_INITGROUPS */
	/* change real and effective user/group-id */
	if (setgid(pw->pw_gid)) {
	    util_warn_strerr("cannot change GID.");
	    util_write_string(521, "Oops! Cannnot change GID.");
	    exit(121);
	}
	if (setuid(pw->pw_uid)) {
	    util_warn_strerr("cannot change UID or UID.");
	    util_write_string(520, "Oops! Cannnot change UID.");
	    exit(120);
	}

	util_write_string(220, "OK. I'll try to execute command...");
	execl(SH_EXE, SH_EXE, "-c", opt_c, NULL);
	util_warn_strerr("cannot run %s to %s.", SH_EXE, opt_c);
	util_write_string(523, "Oops! Cannnot execute command.");
	exit(123);
    }

    /* change password for user */
    /*----------------------------------------------------------------------*/

    /* get new passwd */
    util_write_string(300, "You are trusted. Please send new password.");
    pass_new = ReadValue(newpass_buf, sizeof(newpass_buf));
    if (pass_new == NULL) {
	util_warn("new password is not passed.");
	util_write_string(502, "New password required.");
	exit(102);
    }

    if (IsSuitablePasswd(username, pass_new, pass_old) != TRUE) {
	util_warn("new password is not suitable");
	util_write_string(530, "New password is not suitable string.");
	exit(130);
    }
    if (ChangePasswd(username, pass_old, pass_new) != SUCCESS) {
	util_warn("passwd changing failed. (unkown error)");
	util_write_string(539, "Password changing failed.");
	exit(139);
    }

#if 0
    /* If you use NIS or NIS+, do NOT enable this section!		*/
    /* Because NIS maps (NIS+ tables) is NOT updated AT ONCE.		*/
    /* Wait for updating maps (on NIS) or Execute `nisping` (on NIS+).	*/

    /* check new-passwd */
    if (AuthenticatePasswd(username, pass_new) != SUCCESS) {
	util_warn("Passwd changing failed.");
	util_write_string(539, "Unknown error occured.");
	exit(139);
    }
#endif /* 0 */

    util_write_string(230, "OK. Your password has been changed.");
    exit(0);
}

/* truncate string */
static void TruncateString(str, len)
char *str;
int len;
{
    if (strlen(str) > len) {
	str[len] = '\0';
    }
}

/* read value from stdin */
static char *ReadValue(buf, len)
char *buf;
int  len;
{
    char *cr, *val;

    buf[0] = '\0';
    fgets(buf, len, stdin);

    if ((cr = strchr(buf, '\n')) != NULL) {
	*cr = '\0';
    }
    if ((val = strchr(buf, ' ')) != NULL) {
	*val = '\0';
	val++;
    }

    return val;
}
