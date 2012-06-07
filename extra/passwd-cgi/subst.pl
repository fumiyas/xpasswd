#!%PATH_PERL%

open(SUBST, "<subst.def") || die "cannot open subst.def to read\n";
while (<SUBST>) {
    chomp;
    s/^#.*//;
    next if (/^\s*$/);

    s/\s*=\s*/=/;
    /([^=]+)=(.*)/;
    $subst{$1} = $2;
}
close(SUBST);
$pattern = join('|', keys(%subst));

open(TARGET, "<$ARGV[0]") || die "cannot open $ARGV[0] to read\n";
unlink($ARGV[0]);
open(RESULT, ">$ARGV[0]") || die "cannot open $ARGV[0] to write\n";
while (<TARGET>) {
    while (s/%HTML_($pattern)%/$subst{$1}/g) {};
    print RESULT;
}
close(TARGET);
close(RESULT);
