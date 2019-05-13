##############################################################################
#                                                                            #
#   idabench is public domain software and may be freely used and           #
#   distributed with or without modification.                                #
#                                                                            #
#   See file "idabench.terms" for DISCLAIMER OF ALL WARRANTIES.             #
#                                                                            #
##############################################################################

use File::Temp "tempfile";

$head = "Scanning Activity Detected:";
$color = "#dddddd";
#
# Return the string necessary to invoke the tool on each file
#
$individual = sub
{
    $IDABENCH::PORTSCAN_THRESHOLD = ( $IDABENCH::HOSTSCAN_THRESHOLD * 10 ) unless ($IDABENCH::PORTSCAN_THRESHOLD > 0);
    my ($filterfile, $outputfile) = @_;
    my $scrubbedfilter = mkfilter($filterfile);
    my $cmd = "$IDABENCH::TCPDUMP_PLGBIN -t -q -n -r - -F $scrubbedfilter";
    $cmd .= " | perl $IDABENCH::IDABENCH_BIN_PATH/find_scan.pl";
    $cmd .= " $outputfile $IDABENCH::HOSTSCAN_THRESHOLD $IDABENCH::PORTSCAN_THRESHOLD $IDABENCH::resolve_names";
    $cmd .= " && rm $scrubbedfilter";
    unless ( -x $IDABENCH::TCPDUMP_PLGBIN){
        $err .= "########\nPLUGIN FATAL: Plugin error. tcpdump not found. Please install tcpdump \n(http://www.tcpdump.org) to access this capability or remove findscan rules directory from \nsite configuration to avoid this message.\n########\n" ;
        $fail = 1;
        $retcmd = "cat > /dev/null; echo tcpdump not found>$outputfile";
    }
    if ($err){
        print STDERR "$err";
        return ("$retcmd") if ($fail);
    }
    return $cmd;
};

#
# The single argument names the file containing the concatenated
# output from the process above applied with each rule file.
# Now do any processing required on this concatenated output and write
# it to OUTPUT.
#
$aggregate = sub
{
    my $inputfile = shift;
    my $linecount = 0;
    
    print STDOUT "Copying findscan results from $inputfile to html file\n";
    if ( -e "$inputfile") {
       open(RESULTS, "<$inputfile")
	  or die "Can't open $inputfile";
       while (<RESULTS>) {
          ++$linecount;
	  print IDABENCH::OUTPUT $_;
       }
       close(RESULTS);
       print STDOUT "Transferred $linecount lines for findscan\n";
    }
    else {
       print STDOUT "findscan aggregate could not open $inputfile\n";
    }
};

sub mkfilter
# A routine to perform variable substitution & strip out comments in filter files
# This should be a library function.
{
    my $filterfile = shift;
    ($fh, $newfilter) = tempfile("XXXXXXXX", DIR => "$IDABENCH::IDABENCH_SCRATCH_PATH"); 
    open(FILT, "<$filterfile");

    my ($mainsection, %filtervars);
    while (<FILT>)
    {
        chomp;
        $_ =~ s/#.*//;                     # Remove everything right of an octothorpe (#)
        $_ =~ s/\s+$// if ($_);            # Remove trailing whitespace
        unless ($mainsection == 1)      # Do we want to deal with variable assignments in the filter body?
	{
            if ($_ =~ m/^\s*var/)    # if it is an assignment
            {    
                my @namevalue = split /\s+/, ${_}, 4;    # identify NAME/value pairs
                eval ($filtervars{$namevalue[1]} = $namevalue[3]); # add them to the var hash
                undef $_;
            }
	}
    
        next unless ($_);
        $mainsection = 1;       # no more variable assignments

        # This needs to be a little smarter to allow for "src" & "dst" to be
        # expanded across list assignments. Until then, one per variable :-(
        $_ =~ s/\$([a-zA-Z_\-0-9]+)/$filtervars{$1}/g; #substitute variable names for their assigned values

        print $fh ("$_\n");
    }
    close FILT;
    return "$newfilter";
    close "$fh";
}
