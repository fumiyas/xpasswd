/*
    define.h
    Copyright (c) 1997-2002 SATOH Fumiyasu, All rights reserved.
    since 1997/05/23
*/

#ifndef _DEFINE_H_INCLUDED
#define _DEFINE_H_INCLUDED

/* 関数宣言における互換性の確保用マクロ  K&R-C <-> ANSI-C */
#ifdef __STDC__
# define _(args)		args
#else /* __STDC__ */
# define _(args)		()
#endif /* __STDC__ */

typedef int BOOL;
#define	TRUE		1
#define FALSE		0

typedef int RESULT;
#define SUCCESS		1
#define FAILURE		0

#define MAXARGC		 50
#define MAXARGVLEN	100
#define MAXIN		 50

#endif /* _DEFINE_H_INCLUDED */
