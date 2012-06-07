/*
    chpasswd.h
    Copyright (c) 1997-2002 SATOH Fumiyasu, All rights reserved.
*/

#ifndef _CHPASSWD_H_INCLUDED
#define _CHPASSWD_H_INCLUDED

#include "define.h"

RESULT ChangePasswd _((char *username, char *pass_old, char *pass_new));
BOOL IsSuitablePasswd _((char *user, char *pass_new, char *pass_old));

#endif /* _CHPASSWD_H_INCLUDED */
