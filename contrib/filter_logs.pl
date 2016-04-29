#!/usr/bin/perl -Tw
#
# filter_logs.pl - Simple script to filter service.log
#
# Copyright (c) 2008-2010 Matthias Eckert
#
# Usage:
#  cat log/service.log | contrib/filter_logs.pl > service.log.filtered
#
################################################################

use strict;
use warnings;

my %CONN = ();
my $num = 0;
my $key;
my $re;
my $line;
my $max;


my ($date, $time, $session, $service, $portproto, $cpid, $ipport, $entrytype, $content);


while ($line = <>) {
    next if (! defined ($line) || ! $line);
    if ($line =~ /\]\s\[redirect\s\d+\]\s/) {
        ($date, $time, $session, $service, $cpid, $ipport, $content) = split (/\s/, $line, 7);
        $session =~ s/.*?\[(.*?)\].*?/$1/;
        $service =~ s/.*?\[(.*?)\].*?/$1/;
        $ipport =~ s/.*?\[(.*?)\].*?/$1/;
        $cpid =~ s/.*?\[(.*?)\].*?/$1/;
        $CONN{$num}{regex} = "$session.*?$service.*?$cpid.*?$ipport";
        $num++;
    }
    else {
        ($date, $time, $session, $service, $cpid, $portproto, $ipport, $entrytype, $content) = split (/\s/, $line, 9);
        if (defined ($entrytype) && $entrytype) {
            next if ($entrytype =~ /stat:/);
            if ($entrytype !~ /(disconnect|connection)/i && $entrytype =~ /connect/) {
                $session =~ s/.*?\[(.*?)\].*?/$1/;
                $service =~ s/.*?\[(.*?)\].*?/$1/;
                $portproto =~ s/.*?\[(.*?)\].*?/$1/;
                $ipport =~ s/.*?\[(.*?)\].*?/$1/;
                $cpid =~ s/.*?\[(.*?)\].*?/$1/;
                $CONN{$num}{regex} = "$session.*?$service.*?$cpid.*?$portproto.*?$ipport";
                $num++;
            }
        }
    }
    foreach $key (keys %CONN) {
        next if (defined ($CONN{$key}{closed}) && $CONN{$key}{closed});
        $re = qr/$CONN{$key}{regex}/;
        if ($line =~ $re) {
            if ($line =~ /\]\sconnect$/ || $line =~ /\[redirect\s\d+\]/) {
                next if (defined ($CONN{$key}{opened}) && $CONN{$key}{opened});
                $CONN{$key}{opened} = 1;
            }
            if ($line =~ /\]\sdisconnect/ || $line =~ /\[redirect\s\d+\]/) {
                $CONN{$key}{closed} = 1;
            }
            $CONN{$key}{string} .= "$line";
            last;
        }
    }
}


$max = keys %CONN;
foreach $key (0..$max) {
    if (defined ($CONN{$key}) && defined ($CONN{$key}{string}) && $CONN{$key}{string}) {
        print STDOUT "$CONN{$key}{string}";
        print STDOUT "[...]\n" if (defined($CONN{$key+1}));
    }
}
exit 0;
