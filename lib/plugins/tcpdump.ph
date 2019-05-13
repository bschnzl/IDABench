##############################################################################
#                                                                            #
#   idabench is public domain software and may be freely used and           #
#   distributed with or without modification.                                #
#                                                                            #
#   See file "idabench.terms" for DISCLAIMER OF ALL WARRANTIES.             #
#                                                                            #
##############################################################################
use Socket;
use DB_File;
use File::Temp "tempfile";

$head = "tcpdump: Context (Packet Header) Pattern Matches";
$color = "#eeeeee";
#
# Return the string necessary to invoke the tool on each file
#
$individual = sub
{
    my ($filterfile, $outputfile) = @_;
    my $scrubbedfilter = mkfilter($filterfile);
    if ( -x $IDABENCH::TCPDUMP_PLGBIN){
        return "$IDABENCH::TCPDUMP_PLGBIN -S -n -r - -F $scrubbedfilter > $outputfile && rm $scrubbedfilter";
    } else {
        my $err = "########\nPLUGIN FATAL: Plugin error. tcpdump not found. Please install tcpdump \n(http://www.tcpdump.org) to access this capability or remove tcpdump rules directory from \nsite configuration to avoid this message.\n########\n" ;
        print STDERR "$err";
        return ("cat > /dev/null; echo tcpdump not found>$outputfile");
    }
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
    
    print STDOUT "Cleaning $inputfile.\n";

    open(CLEAN, ">${inputfile}.cleaned") or 
            die "Can't open ${inputfile}.cleaned";

    my $inlines = 0;
    open(TEXTFILE, "<${inputfile}") or die "Can't open ${inputfile}";
    while (<TEXTFILE>) {
       ++$inlines;
       next if /gre-proto/;
       next if /trunc/;
       print CLEAN $_;
    }
    close(CLEAN);
    close(TEXTFILE);
    #
    # Remove the original txt file.
    #
    unlink("${inputfile}");
    rename("${inputfile}.cleaned", "${inputfile}");

    print STDOUT "Text file ${inputfile} ($inlines lines) cleaned of tcpdump exceptions.\n";
    #
    # Call script sort_and_resolve to sort the output file by IP address
    # and resolve the DNS names.
    #

    &sort_and_resolve($inputfile, $IDABENCH::resolve_names);

    #
    # Add the output from the cleaning, sorting, and resolving to the HTML file.
    #
    print STDOUT "Copying ${inputfile}.sorted to html file.\n";

    open(TEXTFILE, "<${inputfile}.sorted") or 
      die "Can't open ${inputfile}.sorted";
    while (<TEXTFILE>) {
       $_ =~ s/</&lt;/gm;
       $_ =~ s/>/&gt;/gm;
       print IDABENCH::OUTPUT $_;
    }
    close(TEXTFILE);
};

our $db_file;
END
{
    if($db_file)
    {
    	unlink($db_file) or die ("Couldn't unlink $db_file : $!")
    }
}
#
# First argument: name of input file
# Second argument: "yes" to resolve names.  Any other value will not resolve names.
#
sub sort_and_resolve
{
    
    # Fetch a non-existant temporary file name.  END block above makes sure it
    # disappears when we exit.
    #
    my %fh;
    ($fh, $db_file) = tempfile("XXXXXXXX", DIR => "$IDABENCH::IDABENCH_SCRATCH_PATH");
    #
    #
    # Tie the hash %h to the btree format of the Berkeley DB module. The hash %h
    # is the tcpdump output line indexed by the source IP address concatenated 
    # with the time.
    #
    tie %fh, "DB_File", $db_file, O_RDWR|O_CREAT, 0644, $DB_BTREE;

    #
    # Main Program, Initialize Name/IP hash.
    #
    %ip_name = ();
    $filein = $_[0];
    $resolve_names = $_[1];
    print STDOUT "sort_and_resolve called with input file $filein\n";
    open(IN,"$filein");
    #
    # Read through the entire text file. Construct a key for each record consisting
    # of the source IP address of the record followed by the time tcpdump recorded
    # the record. This will automatically sort the records by IP and time.
    #
    my ($key, $dataline);

    my $lcount = 0;
    
    while (<IN>) {
       ++$lcount;
       # Newer tcpdump format may not begin with src address. Look for the first
       # appearance of a nnn.nnn.nnn.nnn construct and pray that it's the src addr.
       my @fields = split(/\s+/ , $_);
       my @addr;
       foreach my $field (@fields) {
	  if ( $field =~ /[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/){
             @addr = split(/\./ , $field);
             last;
	  }
       }
       my $string_ip = sprintf("%03d%03d%03d%03d", $addr[0], $addr[1], $addr[2], $addr[3]);
       $key = sprintf("%s %s", $string_ip, $fields[0]);
       $fh{$key} = $_;
    }
    close(IN);

    my $filenameout = $filein . ".sorted";

    my $oldsrcip = "0.0.0.0";
    my $olddataline = "gobbledeegook";
    open(OUT,">$filenameout");
    #
    # Cycle through our DB file in sorted order and resolve the IP addresses in
    # each line.
    #

    my $dcount = 0;
    while (($key, $dataline) = each %fh)
    {
        ++$dcount;
	my (@addrs, @fields);
	@fields = split(/\s+/ , $dataline);
	foreach $field (@fields) {
            if ( $field =~ /[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/){
        	push @addrs, $field;
            }
	}
	next unless @addrs;
	my $src_ip = $addrs[0];
	my $dst_ip = $addrs[1];

       my @src = split(/\./, $src_ip);
       pop (@src) if (scalar(@src) == 5);
       $srcip = join('.', @src);
       $srcname = resolve($srcip) if (($resolve_names eq "yes") and ($srcip ne $oldsrcip));

       $dst_ip =~ tr/://d;
       @dst = split(/\./, $dst_ip);
       pop (@dst) if (scalar(@dst) == 5);
       my $dstip = join('.', @dst);
       my $dstname = resolve($dstip) if ( $resolve_names eq "yes" );

       if ($srcip eq $oldsrcip)
       {
	  if ($dataline ne $olddataline)
	  {
       	      $dataline =~ s/$srcip/$srcname/ if ($srcname);
              $dataline =~ s/$dstip/$dstname/ if ($dstname);
              print OUT $dataline;
	       $olddataline = $dataline;
	  }
       }
       else
       {
	  print OUT "\n$srcip > $dstip\n";
	  $dataline =~ s/$srcip/$srcname/ if ($srcname);
	  $dataline =~ s/$dstip/$dstname/ if ($dstname);
	  print OUT $dataline;
	  $oldsrcip = $srcip;
	  $olddataline = $dataline;
       }
    }
    close(OUT);
    untie(%fh);
    print STDOUT "Records read = $lcount, Database elements =$dcount\n";
}

sub resolve
{
#
# Given an IP address: xxx.xxx.xxx.xxx, return a machine name if it exists.
# Keep found names in a hash table to prevent repetitive name lookups.
#

   my $param = shift(@_);
   my @octets = (0) x 4;
   @octets = split(/\./, $param);
   my $ip_addr = join('.', @octets);
   
    
   if ($ip_name{$ip_addr}) {
     $name = $ip_name{$ip_addr};
   } elsif (($octets[3] == 0) or ($octets[0] == 255) or 
         ($octets[1] == 255) or ($octets[2] == 255) or 
         ($octets[3] == 255)) {
         $name = $ip_addr;
         $ip_name{$ip_addr} = $ip_addr;
   } else {
#
# call system to fetch hostname
#   
     my $binip = pack "c4", @octets;
     my @info = gethostbyaddr($binip, AF_INET);
     $name = $info[0] ? $info[0] : "";
    
     $ip_name{$ip_addr} = $name;
   }
   return $name;

}

sub mkfilter
# A routine to perform variable substitution & strip out comments in filter files
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
