#!/usr/bin/perl
use Net::DNS;
$domain=shift;
get_MX($domain);

sub get_MX {
    $name = shift;
    print "Results of MX search for $name\n";
    $res = new Net::DNS::Resolver;
    @mx = mx($res, $name);
    if (@mx) {
         foreach $rr (@mx) {
             print $rr->preference, " ", $rr->exchange, "\n";
         }
    }
}


