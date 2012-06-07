#!%PATH_PERL% -w
#
# Password server for POP clients
# Copyright (c) 1998-2002 SATOH Fumiyasu, All rights reserved.
#
# version: 1.0.0 alpha2 (1999/01/14 - since 1998/02/05)
#
# related files:
#	%PATH_XPASSWD%
#
# maked by:
#	%USERNAME% at %HOSTNAME%:%CWD%

use strict;
use 5.000;

my($user, $pass, $newpass);
$|=1;

# get username
&send('200 I am poppassd by xpasswd. Hello, who are you?');
$user = &recv('^user (.*)', '500 Username required.');

# get password and authenticate by xpasswd
&send('300 Please send your password now.');
$pass = &recv('^pass (.*)', '500 Password required.');
&xpasswd('-a', "user $user\npass $pass\n");

# get new password and change password by xpasswd
&send('200 Your new password please.');
$newpass = &recv('^newpass (.*)', '500 New password required.');
&xpasswd('--', "user $user\npass $pass\nnewpass $newpass\n");

# send result
&send('200 Password changed, Thank you.');
&recv('^quit$', '500 Quit required.');

# success!
&send('200 Bye-bye');
exit(0);

# send message to client
sub send
{
    print @_, "\r\n";
}

# receive message from client
sub recv
{
    my($pattern, $error) = @_;

    # read and cut `\r\n'
    $_ = <>;
    $_ =~ s/[\r\n]$//g;

    # if unexpected pattern
    unless (/$pattern/) {
	&send($error);
	exit(1);
    }

    $1;
}

# talk to xpasswd
sub xpasswd
{
    my($option, $input) = @_;

    pipe(PREAD, PWRITE);
    my($pid) = fork();
    if ($pid == 0) {	# child
	open(STDIN, "<&PREAD");
	close(PREAD);
	exec("%PATH_XPASSWD%", $option);
    }
    # to prevent `perl -w' warning `Statement unlikely to be reached'
    if ($pid == 0) {	# child
	&send("500 Unable to exec xpasswd to change password.");
	exit(5);
    }

    # parent
    close(PREAD);

    # set PWRITE to unbufferd mode
    select((select(PWRITE), $| = 1)[0]);

    print PWRITE $input;
    waitpid($pid, 0);
    my($result) = $? >> 8;
    if ($result == 2) {
	&send("500 Username or password is incorrect.");
	exit(5);
    }
    if ($result == 8) {
	&send("500 New password is not suitable string.");
	exit(5);
    }
    if ($result == 9) {
	&send("500 Unable to change password by xpasswd.");
	exit(5);
    }
    if ($result != 0) {
	&send("500 Unexpected error by xpasswd.");
	exit(5);
    }
}

#/*
# * poppassd.c
# *
# * Eudora と NUPOP 用のパスワード変更サーバ
# *
# * John Norstad
# * Academic Computing and Network Services
# * Northwestern University
# * j-norstad at nwu.edu
# *
# * Based on earlier versions by Roy Smith <roy at nyu.edu> and Daniel
# * L. Leavitt <dll.mitre.org>.
# * 
# * 翻訳(一部のみ): 佐藤文優
# *
# * このプログラム自身が実際にパスワードを変更することはしない。単にやってくる
# * リクエストを聞いて、必要な情報(ユーザ名、旧パスワード、新パスワード)を
# * 取り込み、/bin/passwd を実行して仮想端末のペアを介して対話する。
# * この方法の利点は、パスワード・ファイル形式の知識(たとえば dbx ファイルが
# * あり、再構築に必要)や、/bin/passwd とその仲間が利用する、ファイルをロック
# * するための(文書化されていない)プロトコルの知識を得る必要がない点にある。
# *
# * The current version has been tested at NU under SunOS release 4.1.2 
# * and 4.1.3, and under HP-UX 8.02 and 9.01. We have tested the server 
# * with both Eudora 1.3.1 and NUPOP 2.0.
# *
# * Other sites report that this version also works under AIX and NIS,
# * and with PC Eudora.
# *
# * Note that unencrypted passwords are transmitted over the network.  If
# * this bothers you, think hard about whether you want to implement the
# * password changing feature.  On the other hand, it's no worse than what
# * happens when you run /bin/passwd while connected via telnet or rlogin.
# * Well, maybe it is, since the use of a dedicated port makes it slightly
# * easier for a network snooper to snarf passwords off the wire.
# *
# * NOTE: In addition to the security issue outlined in the above paragraph,
# * you should be aware that this program is going to be run as root by
# * ordinary users and it mucks around with the password file.  This should
# * set alarms off in your head.  I think I've devised a pretty foolproof
# * way to ensure that security is maintained, but I'm no security expert and
# * you would be a fool to install this without first reading the code and
# * ensuring yourself that what I consider safe is good enough for you.  If
# * something goes wrong, it's your fault, not mine.
# *
# * The front-end code (which talks to the client) is directly 
# * descended from Leavitt's original version.  The back-end pseudo-tty stuff 
# * (which talks to /usr/bin/password) is directly descended from Smith's
# * version, with changes for SunOS and HP-UX by Norstad (with help from
# * sample code in "Advanced Programming in the UNIX Environment"
# * by W. Richard Stevens). The code to report /bin/passwd error messages
# * back to the client in the final 500 response, and a new version of the
# * code to find the next free pty, is by Norstad.
# *        
# * Should be owned by root, and executable only by root.  It can be started
# * with an entry in /etc/inetd.conf such as the following:
# *
# * poppassd stream tcp nowait root /usr/local/bin/poppassd poppassd
# * 
# * and in /etc/services:
# * 
# * poppassd	106/tcp
# *
# * Logs to the local2 facility. Should have an entry in /etc/syslog.conf
# * like the following:
# *
# * local2.err	/var/adm/poppassd-log
# */
# 
#/* Modification history.
# *
# * 06/09/93. Version 1.0.
# *
# * 06/29/93. Version 1.1.
# * Include program name 'poppassd' and version number in initial 
# *    hello message.
# * Case insensitive command keywords (user, pass, newpass, quit).
# *    Fixes problem reported by Raoul Schaffner with PC Eudora.
# * Read 'quit' command from client instead of just terminating after 
# *    password change.
# * Add new code for NIS support (contributed by Max Caines).
# *
# * 08/31/93. Version 1.2.
# * Generalized the expected string matching to solve several problems
# *    with NIS and AIX. The new "*" character in pattern strings
# *    matches any sequence of 0 or more characters.
# * Fix an error in the "getemess" function which could cause the
# *    program to hang if more than one string was defined in the
# *    P2 array.
# *
# * 03/29/94. Version 1.3.
# * Incorporated Andy Sun's changes for ULTRIX.
# *
# * 04/06/94. Version 1.4.
# * Incorporated Andy Sun's changes for OSF/1
# */
#
#/* Andy Sun's comments about ULTRIX: (andy at ie.utoronto.ca):
# *
# * I have modified poppassd v1.2 to work under UItrix and I am keeping
# * my promise by sending you the patch (a very tiny one). The patch basically
# * does two things:
# *
# *       - added codes to Ultrix /bin/passwd prompts
# *       - use BSD4.2 syslog by specifying -DULTRIX in CFLAGS
# *
# * The real trick for getting poppassd to work under ULtrix is to add the
# * compile option "-YPOSIX". Apparently, Ultrix supports three different
# * types of termios (BSD, SYSV and POSIX) and poppassd will only work
# * by using the POSIX version of termios. So for people to compile poppassd
# * for Ultrix using the following patch, their CFLAGS and LFLAGS will have
# * to look like:
# *
# *       CFLAGS = -g -YPOSIX -DULTRIX
# *       LFLAGS = -g -YPOSIX -DULTRIX
# *
# * BTW, the machine I am using is a DECsystem 500/200 running
# * Ultrix 4.3 (Rev. 44). The patch itself should work for older versions
# * of Ultrix, but -YPOSIX cc option may vary.
# */
#
#/* Andy Sun's comments about OSF/1:
# *
# * There is one catch in getting poppassd to work under OSF/1. I coudn't
# * get poppassd to work properly (it executes /bin/passwd alright but the
# * child process won't exit so poppassd will get stuck) under OSF/1 until
# * I ran "mkpasswd -v /etc/passwd" to create the hash database. If I don't
# * use the hash database command to create the appropriate files under /etc,
# * /bin/passwd will display the line:
# *
# *  "Hashed database not in use, only /etc/passwd text file updated."
# *
# * at the very end of /bin/passwd which is not anticpated by poppassd. I
# * tried to flush this extra output but couldn't seem to make it work.
# * So my modifications will only work on systems that have run mkpasswd.
# * This is a minor problem because all mkpasswd does is create a hash
# * table of the entries in /etc/passwd to facilitate getpwuid() and
# * getpwnam() and it quite harmless.
# *
# */
#
#/* Steve Dorner による簡単なプロトコルの説明:
# *
# * サーバの応答は FTP サーバの応答に似た形式にする。1xx は経過、* 2xx は
# * 成功、3xx は必要な追加情報、4xx は一時的な失敗、そして 5xx が完全な
# * 失敗を示す。それらを一緒に組み立てて、以下のような簡単な対話となる。
# *
# *   S: 200 hello\r\n
# *   E: user yourloginname\r\n
# *   S: 300 please send your password now\r\n
# *   E: pass yourcurrentpassword\r\n
# *   S: 200 My, that was tasty\r\n
# *   E: newpass yournewpassword\r\n
# *   S: 200 Happy to oblige\r\n
# *   E: quit\r\n
# *   S: 200 Bye-bye\r\n
# *   S: <closes connection>
# *   E: <closes connection>
# */
