#!/usr/bin/perl -w
#
# gen_config.pl - Simple script for ip address configuration changes (useful for Live-CDs)
#
# Copyright (c) 2009 Matthias Eckert
#
# Usage:
#  contrib/gen_config.pl [config/inetsim.conf]
#
################################################################

use strict;
use warnings;

my $CONF;
my @BUF = ();
my $ADDRESS;


sub get_address {
    my @erg = ();
    
    chomp(@erg=`/sbin/ifconfig 2>/dev/null`);
    foreach (@erg) {
        if (/[\t\s]+inet\s+(addr|Adresse):(\d+\.\d+\.\d+\.\d+)\s+/ && ! /127\.0\.0\.1/) {
            return $2 if (defined ($2) && $2);
        }
    }
    return undef;
}





if (@ARGV && -f $ARGV[0] && ! -d $ARGV[0]) {
    $CONF = $ARGV[0];
}
else {
    $CONF = "/etc/inetsim/inetsim.conf";
}
$ADDRESS = &get_address;
if (defined ($ADDRESS) && $ADDRESS) {
    if (open(IN, $CONF)) {
        while (<IN>) {
            s/^#?service_bind_address.*$/service_bind_address\t$ADDRESS/g;
            s/^#?dns_default_ip.*$/dns_default_ip\t$ADDRESS/g;
            s/^#?redirect_external_address.*$/redirect_external_address\t$ADDRESS/g;
            push (@BUF, $_);
        }
        close IN;
        if (open(OUT, ">$CONF")) {
            foreach (@BUF) {
                print OUT $_;
            }
            close OUT;
        }
    }
}


exit 0;
