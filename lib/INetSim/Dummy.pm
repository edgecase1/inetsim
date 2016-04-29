# -*- perl -*-
#
# INetSim::Dummy - Base package for Dummy::TCP and Dummy::UDP
#
# (c)2008 Matthias Eckert, Thomas Hungenberg
#
# Version 0.1   (2008-03-06)
#
#############################################################
#
# History:
#
# Version 0.1   (2008-03-06) me
# - initial version
#
#############################################################

package INetSim::Dummy;

use strict;
use warnings;
use base qw(INetSim::GenericServer);

# no shared functions

1;
#
