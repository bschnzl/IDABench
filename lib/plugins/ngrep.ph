##############################################################################
#                                                                            #
#   idabench is public domain software and may be freely used and           #
#   distributed with or without modification.                                #
#                                                                            #
#   See file "idabench.terms" for DISCLAIMER OF ALL WARRANTIES.             #
#                                                                            #
##############################################################################
$head = "ngrep: Content (Data) Pattern Matches";
$color = "#cccccc";
#
# Return the string necessary to invoke the tool on each file
#
$individual = sub
{
    my ($err, $fail, $retcmd, @rule);
    my ($filterfile, $outputfile) = @_;
    $err .= "Cannot open $filterfile for ngrep\n" unless (open(NGRULES, $filterfile));
    while (<NGRULES>){
        chomp;
        push @rule, $_ unless ($_ =~ /^(\s*$|\s*#)/)
    }
    close NGRULES; 
    my ($regexp, $pcap, $switches) = @rule[0,1,2];
    if ($switches){
        $switches =~ s/[^XwixvA0-9]//g;   # Only allow through sensible
        $switches = "-" . "$switches";    # switches
    }
    unless ( -x $IDABENCH::NGREP_PLGBIN){
        $err .= "########\nPLUGIN FATAL: Plugin error. ngrep not found. Please install ngrep \n(https://github.com/jpr5/ngrep) to access this capability or remove ngrep rules directory from \nsite configuration to avoid this message.\n########\n" ;
        $fail = 1;
        $retcmd = "cat > /dev/null; echo ngrep not found>$outputfile";
    }
    if ($err){
        print STDERR "$err";
        return ("$retcmd") if ($fail);
    }
    print STDERR "returning: \"$IDABENCH::NGREP_PLGBIN $switches -qtI - \'$regexp\' \'$pcap\' >$outputfile\"\n";
    return ("$IDABENCH::NGREP_PLGBIN $switches -qtI - \'$regexp\' \'$pcap\' >$outputfile");
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
    
    if(!open(NGREP_INP, $inputfile))
    {
    	print IDABENCH::OUTPUT "ngrep failed";
	return;
    }
#    print IDABENCH::OUTPUT "-" x 20, "\n";
    while (<NGREP_INP>)
    {
	$_ =~ s/</&lt;/gm;
	$_ =~ s/>/&gt;/gm;
	$_ =~ s/^input: -$//;
	next if $_ =~ /^$/;
	print IDABENCH::OUTPUT $_;
    }

    close NGREP_INP;
};

