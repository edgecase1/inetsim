# -*- perl -*-
#
# INetSim::Quotd - Base package for Quotd::TCP and Quotd::UDP
#
# (c)2007 Thomas Hungenberg, Matthias Eckert
#
# Version 0.21  (2007-04-26)
#
# For history/changelog see bottom of this file.
#
#############################################################

package INetSim::Quotd;

use strict;
use warnings;
use base qw(INetSim::GenericServer);


my $selected_author = undef;
my $selected_quote = undef;


sub select_quote{
    my $serviceName = shift;
    my $quotesfilename = &INetSim::Config::getConfigParameter("Quotd_QuotesFileName");
    my $count = 0;
    my $author;
    my $quote;
    my $selected;
    my @authors;
    my @quotes;
    my $line;

    if (! open(FH, $quotesfilename)) {
	# unable to open quotes file
	&INetSim::Log::MainLog("Warning: Unable to open quotes file '$quotesfilename': $!.", $serviceName)
    }
    else {
	while ($line=<FH>) {
	    chomp($line);
	    if ($line !~ /^\#/){
		my $author = $line;
		my $quote = $line;
		$author =~ s/^.*\-\-\-(.*)$/$1/;
		$quote =~ s/^(.*)\-\-\-.*$/$1/;
		$author =~ s/^\s+//;
		$author =~ s/\s+$//;
		$quote =~ s/^\s+//;
		$quote =~ s/\s+$//;
		if (($quote ne "") && ($author ne "")) {
		    push(@authors, $author);
		    push(@quotes, $quote);
		}
	    }
	    else {
		next;
	    }
	}
	close FH;
    }

    if (! scalar @quotes) {
	&INetSim::Log::MainLog("Warning: No quotes available. Using built-in dummy quotes instead.", $serviceName);
	# doppelt, wegen rand()
	push(@quotes, "No quotes today :-)");
	push(@quotes, "No quotes today :-)");
	push(@authors, "Matze");
	push(@authors, "Matze");
    }
    $count = @quotes;
    $selected = int(rand($count));
    return ($authors[$selected], $quotes[$selected]);
}


1;
#############################################################
#
# History:
#
# Version 0.21  (2007-04-26) th
# - use getConfigParameter
#
# Version 0.2   (2007-04-24) th
# - replaced die() call if quotes file not available
# - log warning if quotes file not available or empty
#
# Version 0.1   (2007-03-26) th
#
#############################################################
