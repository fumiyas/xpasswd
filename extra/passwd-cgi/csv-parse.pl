# csv-parse.pl
# nishino at cij.co.jp	1996/05/24
# fumiya at cij.co.jp	1996/08/12
#
# Description:
#
# Usage:
#
# Example:
#	@record = &csv_parse(STDIN);
#	@record = &csv_pickup("./data.csv", $field_number, "384");
#	@record = &csv_pickup("./data.csv", $record_number);
#	$csv_out = &csv_pack(@record);
#

#
# Read 1 record , fields array return.
#
sub csv_parse {
    local($STREAM) = $_[0];
    local($c, $i, $j);
    local($field);
    local(@fields);

    $c = &getch($STREAM);

    while ($c) {

	if ($c eq '"') {		# Literal field
	    $c = &getch($STREAM);
	    for (;;) {

		while ($c ne '"') {	# search double quote
		    $field .= $c;
		    $c = &getch($STREAM);
		}
		last if $c eq "";

		# count sequence of double quote
		for ($i = 0; $c eq '"'; $i++) {
		    $c = &getch($STREAM);
		}
		last if $c eq "";

		for ($j = 0; $j < $i / 2 - ($i % 2) ;$j++) {
		    $field .= '"';
		}

		# $i == even : inbind double quote
		if ($i % 2) { # odd : end of field, or inbind + end of field
		    last;
		}
	    }

	} elsif ($c =~ /\d/) {		# Numeric field
	    do {
		$field .= $c;
		$c = &getch($STREAM);
	    } while ($c =~ /\d/); 

	} elsif ($c eq ',') {		# Blank field
	    push(@fields, $field);
	    $field = "";
	    $c = &getch($STREAM);

	} elsif ($c =~ /[ \t]/) {	# skip white space
	    $c = &getch($STREAM);

	} elsif ($c eq "\n") {		# record end
	    push(@fields, $field);
	    last;

	} else {			# invalid field
	    die "illegural field Character:($c)";
	}
    }
    @fields;
}

#
# write 1 record.
#
sub csv_pack {
    local(@fields) = @_;
    local(@record);
    
    foreach (@fields) {
	s/"/""/g;
	substr($_, 0, 0) = '"';
	$_ .= '"';
        push(@record, $_);
    }
    join(',', @record);
}

#
#  Return the next character from specified stream.
#
undef @stream_buf;

sub getch {
    local($STREAM) = @_;

    if (@stream_buf == 0) {
	if ($_ = <$STREAM>) {
	    @stream_buf = unpack("C*", $_);
	} else {
	    return "";
	}
    }
    pack("C", shift(@stream_buf));
}

#
# Push character back onto input
#
sub ungetch {
    unshift(@stream_buf, unpack("C", $_[0]));
}

#
# Pickup csv format entry
#
sub csv_pickup {
    local($file, $field, $value) = @_;
    local(@p);
    local($i);

    open(FD, $file) || die("cannot open $file :");
    if ($value ne "") {
	while (@p = &csv_parse(FD)) {
	    last if $p[$field] eq $value;
	}
    } else {
	$field++;
	for ($i = 0; ($i ne $field) && (@p = &csv_parse(FD)); $i++) {};
    }
    close($FD);
    @p;
}

1;
