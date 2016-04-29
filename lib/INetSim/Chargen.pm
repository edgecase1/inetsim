# -*- perl -*-
#
# INetSim::Chargen - Base package for Chargen::TCP and Chargen::UDP
#
# RFC 864 - Character Generator Protocol
#
# (c)2007 Matthias Eckert, Thomas Hungenberg
#
# Version 0.1   (2007-03-24)
#
# For history/changelog see bottom of this file.
#
#############################################################

package INetSim::Chargen;

use strict;
use warnings;
use base qw(INetSim::GenericServer);

sub chars{
    my $self = shift;
    my $offset = shift;
    my $chars;
    foreach (0..94){
	$chars .= chr($_ + 32);
    }
    $chars .= $chars;
    return substr($chars, $offset, 72);
}


1;
#############################################################
#
# History:
#
# Version 0.1   (2007-03-24) th
#
#############################################################
