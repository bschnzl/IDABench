#! /usr/bin/perl
##############################################################################
#                                                                            #
#   idabench is public domain software and may be freely used and           #
#   distributed with or without modification.                                #
#                                                                            #
#   See file "idabench.terms" for DISCLAIMER OF ALL WARRANTIES.             #
#                                                                            #
##############################################################################
#
# statistics.ph             - IDABENCH Version 1.0
#
#
#  Script to read a raw tcpdump hourly file, look at the packets,
#  and produce some statistics about the traffic seen in that file.
#  Optionally uses Compress::Zlib Perl module to directly read gzipped files.
#
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#     |0               1               2               3              |
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#     |0                   1                   2                   3  |
#     |0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1|
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  0  |                          timestampsec                         | Header
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  4  |                          timestampusec                        |
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  8  |                             fsize                             |
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# 12  |                             ssize                             |
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#                                                                      
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  0  |                    Ethernet Destination                       |
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  4  |                               |        Ethernet Source        |
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  8  |                                                               |
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# 12  |           Ethertype           |Version|  IHL  |Type of Service|
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# 16  |          Total Length         ||         Identification       |
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# 20  |Flags|      Fragment Offset    |  Time to Live |    Protocol   |
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# 24  |         Header Checksum       |         Source Address        |
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# 28  | Source Address (cont)         |       Destination Address     |
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# 32  | Destination Address (cont)    |                               |
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  
#   option or other header
#  
#     |          Source Port          |       Destination Port        | TCP
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#     |                        Sequence Number                        |
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#     |                    Acknowledgment Number                      |
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#     |  Data |           |U|A|P|R|S|F|                               |
#     | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
#     |       |           |G|K|H|T|N|N|                               |
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# 
#
use Socket;
#
#########################################################################
#
sub itslocal
{
#
# Given an IP address: xxx.xxx.xxx.xxx, return true if it is an "internal"
# address.
#
   use integer;

   my $addr = shift;
   my $addr_pack = inet_aton($addr);
   my $addr_int = vec($addr_pack, 0, 32);
   my $local = 0;
   #
   for (my $index=0; $index < scalar(@internal_ip); $index++) {
      if (($addr_int & $internal_mask[$index]) == $internal_ip[$index]) {
         $local++;
         return 1;
      }
   }
   return 0;
}
#########################################################################
#
sub numerically  { $a <=> $b;}
sub descending  { $b <=> $a;}
#
#########################################################################
#
sub resolve
{
#
# Given an IP address: xxx.xxx.xxx.xxx, return a machine name if it exists.
#

   my $param = shift(@_);
   my @octets = (0) x 4;
   @octets = split(/\./, $param);
   my $ip_addr = join('.', @octets);
   my $name;


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
      if ($resolve_names eq "yes") {
	my @info = gethostbyaddr($binip, AF_INET);
      }
      $name = $info[0] ? $info[0] : $ip_addr;

      $ip_name{$ip_addr} = $name;
   }
   return $name;

}
#
#########################################################################
#
sub init_state
#
# Subroutine to initialize  the current values of the global variables.
#
{
   %pkt_counter = ();
   %pkt_volume = ();
   %local_count_ip = ();
   %remote_count_ip = ();
   %flg_count = ();
   %conn_counter = ();
   %proto_count = ();
   %proto_vol = ();
   %ip_name = ();
   $pkt_count = 0;
   $tcp_count = 0;
   $pkt_vol = 0;
}
#
#########################################################################
#
# Define some globally used variables for the entire statistics packages.
#
# Define ICMP "type" values as hash.
#
%icmp_types = ();
#
$icmp_types{"3"} = "Dest. Unreach";
$icmp_types{"4"} = "Src Quench";
$icmp_types{"5"} = "Redirect";
$icmp_types{"8"} = "Echo Req.";
$icmp_types{"9"} = "Router Ad";
$icmp_types{"10"} = "Router Sol";
$icmp_types{"11"} = "Time Exc.";
$icmp_types{"12"} = "Param. Prob.";
$icmp_types{"13"} = "Timstamp Req";
$icmp_types{"14"} = "Timstamp Rep";
$icmp_types{"15"} = "Info Req";
$icmp_types{"16"} = "Info Rep";
$icmp_types{"17"} = "Adr Msk Req";
$icmp_types{"18"} = "Adr Msk Rep";
#
# Define an array of "internal" IP addresses.
#
@internal_ip = ( 
                "172.21.0.0", "172.22.0.0", "172.16.22.0",
               );
@internal_mask = (
                "255.255.0.0", "255.255.0.0", "255.255.255.0",
                );
#
for ($index=0; $index < scalar(@internal_ip); $index++) {
   my $int = inet_aton("$internal_ip[$index]");
   $internal_ip[$index] = vec($int,0,32);
}
for ($index=0; $index < scalar(@internal_mask); $index++) {
   my $int = inet_aton("$internal_mask[$index]");
   $internal_mask[$index] = vec($int,0,32);
}
@pkt_directions = ( "External", "Incoming", "Outgoing", "Internal");
#
# Let's look at some specific TCP and UDP ports.
#
@TCP_ports = ( "12345", "12346", "31337", "2049", "2766", "5232", "6000",
               "6667", "20432");
@UDP_ports = ( "1080", "2049", "3128", "6970", "7070", "18753", "20433", 
               "31337");
#
#########################################################################
#
sub printem {
#
# Subroutine to print out the summary of statistics gathered.
#
# Get filehandle from passed parameter.
# 
   my $outfile = shift;
   if ($outfile) {
      open(OUTFILE, ">$outfile");
      $out_fh = *OUTFILE;
   } else {
      $out_fh = *STDOUT;
      $stdout_flag = 1;
   }
#
# Print out the results.
#
   printf $out_fh "\n-------------------------------------------------------------------------\n";
   printf $out_fh ("\nTotals:\n");
   printf $out_fh (" %20.3f Kpackets\n",$pkt_count/1024.0);
   printf $out_fh (" %20.3f Megabytes\n",$pkt_vol/1048576.0);
   
   printf $out_fh "\n-------------------------------------------------------------------------\n";
   printf $out_fh ("\nPer protocol breakout:\n");
   printf $out_fh ("Prot|#    Kpkts     %%     Mbytes     %% |\n");
   printf $out_fh ("    |                                  |\n");
   printf $out_fh ("=== |========== ===== ========== ===== |\n");
   foreach $key ( sort numerically ( keys %proto_count)) {
      printf $out_fh ("%3d |%10.3f %5.1f %10.3f %5.1f |%s\n",
         $key,
         $proto_count{$key}/1024.0, 
         100.0*$proto_count{$key}/$pkt_count,
         $proto_vol{$key}/1048576.0, 
         100.0*$proto_vol{$key}/$pkt_vol,
         $name = getprotobynumber($key)); 
   }
   
   printf $out_fh "\n-------------------------------------------------------------------------\n";
   printf $out_fh ("\nTCP flags statistics:\n");
   printf $out_fh ("(total=%d, percent=%2.2f)\n",$tcp_count,100.0*$tcp_count/$pkt_count);
   printf $out_fh ("Flg #    Kpkts       %%  flags\n");
   printf $out_fh ("=== ========== ======= ======\n");
   foreach $key ( sort numerically ( keys %flg_count)) {
      $fa = "";
      $fa .= "U" if ($key & 0x20);
      $fa .= "A" if ($key & 0x10);
      $fa .= "P" if ($key & 0x08);
      $fa .= "R" if ($key & 0x04);
      $fa .= "S" if ($key & 0x02);
      $fa .= "F" if ($key & 0x01);
      next if ($flg_count{$key} < 100);
      printf $out_fh (" %2x %10.3f  %5.1f %7s\n",
           $key,$flg_count{$key}/1024.0,
           100.0*$flg_count{$key}/$tcp_count,$fa);
   }

#
# Summarize port statistics
#
   printf $out_fh "\n-------------------------------------------------------------------------\n";
   foreach $dir ("Incoming", "Outgoing") {
      printf $out_fh ("\n$dir Packets by protocol:\n\n");
      printf $out_fh (" Protocol  Port          Alias       Kpkts           MBytes\n");
      printf $out_fh (" ========  ====  =============  ==========  ===============\n");   
      foreach $protocol ("tcp", "udp", "icmp") {
         $ip_proto = getprotobyname($protocol);
         foreach $port (sort numerically (keys %{ $pkt_counter{$dir}{$ip_proto}}))
         {
            next unless $pkt_counter{$dir}{$ip_proto}{$port};
            next if ($pkt_counter{$dir}{$ip_proto}{$port} < 100);
            if ($protocol eq "icmp") {
               $svc_name = $icmp_types{$port} if ($icmp_types{$port});
            } else {
               $svc_name = getservbyport($port, $protocol);
            }
            $svc_name = " " unless $svc_name;
            printf $out_fh ("%9s  %4s  %13s  %10.3f  %15.3f\n", 
                            $protocol, 
                            $port, 
                            $svc_name,
                            $pkt_counter{$dir}{$ip_proto}{$port}/1024.0,
                            $pkt_volume{$dir}{$ip_proto}{$port}/1048576.0);
         }
         printf $out_fh "\n-------------------------------------------------------------------------\n";
      }
   }
#
# Summarize connection statistics.
#
   printf $out_fh "\n-------------------------------------------------------------------------\n";
   foreach $dir ("Incoming", "Outgoing") {
      next unless (scalar( keys %{ $conn_counter{$dir} } ) > 0);
      printf $out_fh ("\n$dir Connection Requests:\n");
      printf $out_fh (" Port         Alias     Connections\n");
      printf $out_fh ("===== ============= ===============\n");
      foreach $key ( sort numerically ( keys %{ $conn_counter{$dir} })) {
         next if ($conn_counter{$dir}{$key} < 100);
         printf $out_fh ("%5d %13s %15d\n", 
                          $key, 
                          $svc_name = getservbyport($key, 'tcp'),
                          $conn_counter{$dir}{$key});
      }
   }
#
# Output some statistics about the top N local addresses ,
# and remote addresses.
#
   @locals = sort { $local_count_ip{$b} <=> $local_count_ip{$a} }
                      keys %local_count_ip;
   @remotes = sort { $remote_count_ip{$b} <=> $remote_count_ip{$a} }
                      keys %remote_count_ip;
   
   printf $out_fh "\n-------------------------------------------------------------------------\n";
   printf $out_fh "\nTop Local addresses:\n";
   printf $out_fh "       Local  IP                                      Name      Kpkts\n";
   printf $out_fh "================  ========================================   ========\n";
   $linecount = 0;
   foreach $key ( @locals ) {
      printf $out_fh "%16s %41s %10.3f\n",
                       $key,
                       &resolve($key),
                       $local_count_ip{$key}/1024.0;
      $linecount++;
      last if $linecount > 30;
   }
#
   printf $out_fh "\n-------------------------------------------------------------------------\n";
   printf $out_fh "\nTop Remote addresses:\n";
   printf $out_fh "       Remote IP                                      Name      Kpkts\n";
   printf $out_fh "=================  ========================================  ========\n";
   $linecount = 0;
   foreach $key ( @remotes ) {
      printf $out_fh "%16s %41s %10.3f\n",
                    $key,
                    &resolve($key),
                    $remote_count_ip{$key}/1024.0;
      $linecount++;
      last if $linecount > 30;
   }
   printf $out_fh "\n-------------------------------------------------------------------------\n";
   close($out_fh) unless $stdout_flag;
}
#
#########################################################################
#
# Subroutine to return a method reference. (From "Programming Perl"
# Third Edition, p. 261.
#
#sub get_method_ref {
#   my ($self, $methodname) = @_;
#   my $methref = sub {
#      return $self->$methodname(@_);
#   };
#   return $methref;
#}
#
#########################################################################
#
#
# Subroutine to read the Raw tcpdump file and collect the statistics.
#
sub read_rawfile {
#
   $rawfile = shift;
#
# See if the Compress::Zlib module is available:
#
#   if (eval "require Compress::Zlib") {
#      import Compress::Zlib;
#      $gz = gzopen($rawfile, "rb");
#      $read_sub = get_method_ref($gz, 'gzread');
#      $close_sub = get_method_ref($gz, 'gzclose');
#      $end_of_file = get_method_ref($gz, 'gzerror');
#   } else {
      $open_sub = sub {
         $file_all_read = 0;
         my $file_name = $_[0];
         my $unzip_cmd = "$GUNZIP_CMD -c $rawfile |";      
         return(open(ZIP_CMD, $unzip_cmd));
      };
      $read_sub = sub {
         my $num_to_read = $_[1];
         my $num_bytes = sysread(ZIP_CMD, $_[0], $num_to_read);
         $file_all_read = 1 if($num_bytes < 1);
         return $num_bytes; 
      };
      $close_sub = sub { return(close(ZIP_CMD)) };
      $end_of_file = sub { return $file_all_read; };
#   }
#

   $bytes_read = $read_sub->($record, 24) || return 0;
   
   ($magic_no, $ver_maj, $ver_min, $GMT_off, $sigfigs, $snaplen, $linktype) =
     unpack("I S2 i I3", $record);
   die ("Bad Magic.") unless ($magic_no == eval(hex a1b2c3d4) || $magic_no == eval(hex a1b2cd34) );
#
#printf STDERR "The dump file version number is: %d.%d\n", $ver_maj, $ver_min;
#printf STDERR "The GMT offset is: %d\n", $GMT_off;
#printf STDERR "The timestamp accuracy is: %d\n",$sigfigs;
#printf STDERR "The maximum snapped size is: %d\n", $snaplen;
#printf STDERR "The link type is: %x\n", $linktype;

# End of dump file header parsing

# Start reading in packets
#
   $ipoldtstampsec  = 0;
   $ipoldtstampusec = 0;
#
   until ($end_of_file->()) {
#
# Read next header
#
      $bytes_read = $read_sub->($record, 16) || return 0;
      ($tstampsec, $tstampusec, $fsize, $ssize) = unpack("I4", $record);

print STDERR "tstampsec: $tstampsec\n",
	"tstampusec: $tstampusec\n",
	"fsize: $fsize\n",
	"ssize: $ssize\n";
#	"record: $record\n"

#
# Read packet contents
#
      $bytes_read = $read_sub->($record, $fsize) || return 0;
#     $ethertype = vec($record,6,16);
      $ipcount++;
      $direction = "External";

# Interpret IP packet

      $dtime=(($tstampsec-$ipoldtstampsec)*1048576.0) +
             ($tstampusec-$ipoldtstampusec);
      $dtime = "NA" if ($ipcount == 1 );
      $plen = vec($record,8,16);
      $ipprot = vec($record,23,8);
      $src1 = vec($record,26,8);
      $src2 = vec($record,27,8);
      $src3 = vec($record,28,8);
      $src4 = vec($record,29,8);
      $src = pack("c4", $src1, $src2, $src3, $src4);
      $src_int = vec($src, 0, 32);
#
# Construct full source IP address.
#
      $src_ip = inet_ntoa($src);
#
      $dst1 = vec($record,30,8);
      $dst2 = vec($record,31,8);
      $dst3 = vec($record,32,8);
      $dst4 = vec($record,33,8);
      $dst = pack("c4", $dst1, $dst2, $dst3, $dst4);
      $dst_int = vec($dst, 0, 32);
#
# Construct full destination IP address.
#
      $dst_ip = inet_ntoa($dst);
#
# Increment appropriate counts based on direction of this packet.
#
      if (itslocal($src_ip)) {
         if (itslocal($dst_ip)) {
            $direction = "Internal";
         } else {
            $direction = "Outgoing";
            $local_count_ip{$src_ip}++;
            $remote_count_ip{$dst_ip}++;
         }
      } else {
         if (itslocal($dst_ip)) {
            $direction = "Incoming";
#           $local_count_ip{$dst_ip}++;
            $remote_count_ip{$src_ip}++;
         } else {
            $direction = "External";
         }
      }
#
      $IHL = (vec($record,28,4)&0xf);
      $ip_hdr_offset = ($IHL*4) + 14;

#
# TCP Packets
#
      if (($ipprot == 6)) {
         $sport = vec($record,$ip_hdr_offset,8)*256 + 
                  vec($record,$ip_hdr_offset+1,8);
         $dport = vec($record,($ip_hdr_offset+2),8)*256 +
                  vec($record,$ip_hdr_offset+3,8);
         $seqno = vec($record, ($ip_hdr_offset+4),8)<<24 + 
                  vec($record, ($ip_hdr_offset+5),8)<<16 +
                  vec($record, ($ip_hdr_offset+6),8)<<8 +
                  vec($record, ($ip_hdr_offset+7),8);
         $ackno = vec($record, ($ip_hdr_offset+8),8)<<24 + 
                  vec($record, ($ip_hdr_offset+9),8)<<16 +
                  vec($record, ($ip_hdr_offset+10),8)<<8 +
                  vec($record, ($ip_hdr_offset+11),8);
         $tflags = vec($record, ($ip_hdr_offset+13),8)&0x3f;
#
# TCP flags
#
#
# Incoming/Outgoing connection requests.
#
         $conn_counter{$direction}{$dport}++ if ($tflags == 0x2);
         if (($dport < 1024) or ( grep /$dport/, @TCP_ports)) {
            $pkt_counter{$direction}{$ipprot}{$dport}++;
            $pkt_volume{$direction}{$ipprot}{$dport} += $plen;
         }
         $flg_count{$tflags}++;
         $tcp_count++;
      }
#
# UDP packets
#
      if (($ipprot == 17)) {
         $sport = vec($record,$ip_hdr_offset,8)*256 + 
                  vec($record,$ip_hdr_offset+1,8);
         $dport = vec($record,($ip_hdr_offset+2),8)*256 +
                  vec($record,$ip_hdr_offset+3,8);
         $udp_len = vec($record, ($ip_hdr_offset+4),8)<<8 + 
                  vec($record, ($ip_hdr_offset+5),8);
         $udp_cksum = vec($record, ($ip_hdr_offset+6),8)<<8 +
                  vec($record, ($ip_hdr_offset+7),8);
#
# Incoming/Outgoing UDP packet counts.
#
         if (($dport < 1024) or (grep /$dport/, @UDP_ports)) {
            $pkt_counter{$direction}{$ipprot}{$dport}++;
            $pkt_volume{$direction}{$ipprot}{$dport} += $plen;
         }
      }
#
# ICMP packets
#
      if (($ipprot == 1)) {
         $icmp_type = vec($record,$ip_hdr_offset,8);
         $icmp_code = vec($record,($ip_hdr_offset+1),8);
         $icmp_cksum = vec($record, ($ip_hdr_offset+2),8)<<8 +
                  vec($record, ($ip_hdr_offset+3),8);
         $dport = $icmp_type;
#
# Incoming/Outgoing ICMP packet counts.
#
         $pkt_counter{$direction}{$ipprot}{$dport}++;
         $pkt_volume{$direction}{$ipprot}{$dport} += $plen;
      }
      $ftime = $tstampsec + ($tstampusec/1000000);
#
# global stats
#
      $pkt_count++;
      $pkt_vol += $plen;
#
# protocol stats
#
      $proto_count{$ipprot}++;                  # array prot packet
      $proto_vol{$ipprot} += $plen;
#
#
      $ipoldtstampsec  = $tstampsec;
      $ipoldtstampusec = $tstampusec;
   }
   $close_sub->();
}
;
#  End of statistics.ph
