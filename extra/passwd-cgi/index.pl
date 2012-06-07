#!%PATH_PERL%
#
# CGI: Change password by xpasswd
# Copyright (c) 1997-2002 SATOH Fumiyasu, All rights reserved.
#
# version: 1.2.4 (1999/05/07 - since 1997/11/04)

use 5.004;
#use strict;
use CGI;
use FileHandle;
use IPC::Open2;

use lib '.';
require 'csv-parse.pl';

my $xpasswd	= '%PATH_XPASSWD%';
my $nkf		= '%PATH_NKF%';
my $language	= '%LANGUAGE%';
my $form_tag	= '@tag_([^@_]+)_?([^@_]+)@';
my %record;

if ($language eq "ja") {
    require 'jcode.pl';
    # Output code is JIS, but internal code is EUC
    open(STDOUT, "|$nkf -Ej") || &error("%HTML_ERROR_EXEC_NKF%");
}

# CGI processor
my $cgi_query = new CGI;
# If first try ...
&retry("") if ($cgi_query->request_method() eq 'GET');
# Parse and read items from CGI query
%record = &form_read('item.csv');

my $user = $record{'user'};
my $pass = $record{'pass'};
my $newpass  = $record{'newpass'};
my $newpass2 = $record{'newpass2'};
#&retry("%HTML_RETRY_PASS_INVALID%") if ($newpass =~ /[^\x00-\x7f]/);
&retry("%HTML_RETRY_PASS_MISMATCH%") if ($newpass ne $newpass2);

# Connect to xpasswd via pipe
my $pid = open2(\*READER, \*WRITER, "$xpasswd -v");
close(READER);
print WRITER "user $user\npass $pass\nnewpass $newpass\n";
waitpid($pid, 0);
my $return = $? >> 8;

&retry("%HTML_RETRY_WANT_ALL%")     if ($return==100 || $return==101 || $return==102);
&retry("%HTML_RETRY_UNAUTH_USER%")  if ($return==110 || $return==111);
&retry("%HTML_RETRY_UNAUTH_SHELL%") if ($return==112);
&retry("%HTML_RETRY_UNAUTH_HOME%")  if ($return==113);
&retry("%HTML_RETRY_PASS_WEAKLY%")  if ($return==130);
&error("%HTML_ERROR_UNKNOWN%")      if ($return==139);
&error("%HTML_ERROR_CODE%")         if ($return!=0);

print "Location: %HTML_DONE_URL%\n\n";
exit(0);


sub retry {
    %record = ();
    $record{'user'} = $user;
    $record{'message'} = "%HTML_RETRY_TITLE% <EM>$_[0]</EM><P>" if ($_[0] ne '');
    print $cgi_query->header('text/html');
    &form_make('form.tmpl', 'item.csv', \%record);
    exit(0);
}

sub error {
    print $cgi_query->header('text/html'),
    '<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
    <HTML><HEAD><TITLE>%HTML_ERROR_TITLE%</TITLE></HEAD>
    <BODY BGCOLOR="#ffffff">
    <H1>%HTML_ERROR_TITLE%</H1>
    <HR>
    %HTML_ERROR_SITUATION% <EM><FONT COLOR="#ff0000">',$_[0],'</FONT></EM>
    <UL>',
	'<LI>%HTML_ERROR_USER%:',	$record{'user'},
	'<LI>%HTML_ERROR_AGENT%: ',	$cgi_query->user_agent(),
	'<LI>%HTML_ERROR_CLIENT%: ',$cgi_query->remote_host(),
    '</UL>
    <HR>
    %HTML_ERROR_CONTACT%
    </BODY></HTML>';
    exit(1);
}

sub form_read
{
    my $item = $_[0];
    my $fh_item = new FileHandle;
    my $value;
    my ($name, $face, $type, @args, $view, %record);

    $fh_item->open("<$item");
    unless ($fh_item) {
	&error("%HTML_ERROR_OPEN_ITEM%");
    }
    while (($name, $face, $type, $view) = csv_parse($fh_item)) {
	($type, @args) = split(/,/, $type);
	unless ($type =~ /checkbox/) {
	    $value = $cgi_query->param($name);
	    $value =~ s/\r\n/\n/g;
	    $value =~ s/\r/\n/g;
	} else {
	    $value = "";
	    my $i;
	    for ($i = 0; $i < $cgi_query->param($name); $i++) {
		$value .= $cgi_query->param("$name$i") . ",";
	    }
	    $value =~ s/[,]+/,/g;
	    $value =~ s/^,|,$//g;
	}
	eval("\$value = &jcode'euc(\$value)") if ($language eq "ja");
	$record{$name} = $value;
    }
    $fh_item->close;

    return %record;
}

sub form_make
{
    my ($file_form, $file_item, $p_record) = @_;

    # read item list
    my $fh_item = new FileHandle;
    $fh_item->open("<$file_item") || return 0;
    my %item;
    while (@_ = csv_parse($fh_item)) {
	my ($item_name, $item_face, $item_type, $item_view) = @_;
	$item{$item_name,'name'} = $item_name;
	$item{$item_name,'face'} = $item_face;
	$item{$item_name,'type'} = $item_type;
	$item{$item_name,'view'} = $item_view;
    }
    $fh_item->close;

    # read form , replace variables and print
    my $fh_form = new FileHandle;
    $fh_form->open("<$file_form") || return 0;
    while (<$fh_form>) {
	s/$form_tag/&form_replace($1, $2, \%item, $p_record)/eg;
	print;
    }
    $fh_form->close;
}

# replace variables
sub form_replace
{
    my ($op, $name, $p_item, $p_record) = @_;
    my $form = '';
    my $value;
    my ($type, @args) = split(/,/, $$p_item{$name,'type'});
    my ($mday, $month, $year);
    my $csv = "$name.csv";

    return unless ($op eq 'var');
    $value = $$p_record{$name};

    if ($type eq "raw") {
	return $value;
    }
    if ($type eq "date") {
	$type = "text";
	unless ($value) {
	    my ($mday, $month, $year) = (localtime(time))[3,4,5];
	    $value = sprintf('%d/%02d/%02d', $year+=1900, ++$month, $mday);
	}
    }
    if ($type eq "url") {
	$type = "text";
    }

    if (($type eq "text") || ($type eq "password")) {
	$form .= "<INPUT TYPE=\"$type\" NAME=\"$name\" SIZE=\"$args[0]\" ";
	$form .= "MAXLENGTH=\"$args[1]\" " if ($args[1] > 0);
	$form .= "VALUE=\"$value\">";
    }
    if ($type eq "textarea") {
	$form .= "<TEXTAREA NAME=\"$name\" WRAP=\"VIRTUAL\" COLS=\"$args[0]\"
		ROWS=\"$args[1]\">$value</TEXTAREA>";
    }
    if ($type eq "select") {
	my $fh_csv = new FileHandle;
	my @choice;
	unless ($fh_csv->open("<$csv")) {
	    $form .= "<FONT COLOR=\"#ff0000\">$name(select): ".
		     "%HTML_ERROR_OPEN_CSV%</FONT>";
	    next;
	}
	$form .= "\n\t<SELECT NAME=\"$name\">";
	while (@choice = &csv_parse($fh_csv)) {
	    $form .= "\n\t\t<OPTION VALUE=\"$choice[0]\"";
	    if ($choice[0] eq $value) {
		$form .= " SELECTED";
	    }
	    $form .= ">$choice[1]";
	}
	$form .= "</SELECT>\n";
	$fh_csv->close;
    }
    if ($type eq "checkbox") {
	my $fh_csv = new FileHandle;
	my (@valuelist, @choice, $half, $i);
	unless ($fh_csv->open("<$csv")) {
	    $form .= "<FONT COLOR=\"#ff0000\">$name(checkbox): ".
		     "%HTML_ERROR_OPEN_CSV%</FONT>";
	    next;
	}
	@valuelist = split(/,/, $value);
	for ($half = 0; (@choice = &csv_parse($fh_csv)); $half++) {}
	$half = int($half / 3 + 1);
	$fh_csv->setpos(0);

	$form .= "<TABLE BORDER=1 WIDTH=100%><TR><TD>";
	for ($i = 0; (@choice = &csv_parse($fh_csv)); $i++) {
	    $form .= "\n\t\t";
	    $form .= "<INPUT TYPE=CHECKBOX NAME=\"$name$i\" VALUE=\"$choice[0]\"";
	    if (grep(/^$choice[0]$/, @valuelist)) {
		$form .= " CHECKED";
	    }
	    $form .= ">$choice[1]<BR>";

	    if (($i % $half) == ($half - 1)) {
		$form .= "</TD><TD VALIGN=TOP>";
	    }
	}
	$form .= "</TD></TR>\n".
		 "</TABLE>".
		 "\t\t<INPUT TYPE=HIDDEN NAME=\"$name\" VALUE=\"$i\">";
	$fh_csv->close;
    }

    return $form;
}
