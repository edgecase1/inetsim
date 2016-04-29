# -*- perl -*-
#
# INetSim::FakeTime - Fake time control
#
# (c)2007-2008 Thomas Hungenberg, Matthias Eckert
#
# Version 0.6  (2008-08-27)
#
#############################################################

package INetSim::FakeTime;

use strict;
use warnings;


sub get_faketime {
    return (time() + &INetSim::Config::getConfigParameter("Faketime_Delta"));
}


sub auto_faketime {
    my $serviceName = "autofaketime";
    $0 = "inetsim [$serviceName]";
    local $SIG{'INT'} = 'IGNORE';
    local $SIG{'TERM'} = sub { &INetSim::Log::MainLog("stopped (PID $$)", $serviceName); exit 0;};

    # drop root privileges
    my $runasuser = &INetSim::Config::getConfigParameter("Default_RunAsUser");
    my $runasgroup = &INetSim::Config::getConfigParameter("Default_RunAsGroup");

    my $uid = getpwnam($runasuser);
    my $gid = getgrnam($runasgroup);
    POSIX::setgid($gid);
    my $newgid = POSIX::getgid();
    if ($newgid != $gid) {
	&INetSim::Log::MainLog("failed! (Cannot switch group)", $serviceName);
	exit 0;
    }
    
    POSIX::setuid($uid);
    if ($< != $uid || $> != $uid) {
	$< = $> = $uid; # try again - reportedly needed by some Perl 5.8.0 Linux systems
	if ($< != $uid) {
	    &INetSim::Log::MainLog("failed! (Cannot switch user)", $serviceName);
	    exit 0;
	}
    }

    &INetSim::Log::MainLog("started (PID $$)", $serviceName);

    while (1) {
	sleep(&INetSim::Config::getConfigParameter("Faketime_AutoDelay"));
	&INetSim::Config::setConfigParameter("Faketime_Delta", &INetSim::Config::getConfigParameter("Faketime_Delta") + &INetSim::Config::getConfigParameter("Faketime_AutoIncrement"));
	&INetSim::Log::SubLog("Fake time adjusted, delta now: " . &INetSim::Config::getConfigParameter("Faketime_Delta"), $serviceName, $$);
	&INetSim::Log::SubLog("stat: 1 delta=" . &INetSim::Config::getConfigParameter("Faketime_Delta") ." now=".get_faketime, $serviceName, $$);
    }
}


1;
#############################################################
#
# History:
#
# Version 0.6   (2008-08-27) me
# - added logging of process id
#
# Version 0.5   (2008-03-07) me
# - change process name
#
# Version 0.4   (2007-05-23) th
# - drop root privileges
#
# Version 0.3   (2007-04-25) th
# - moved Faketime_Delta handling to Config.pm
#
# Version 0.2   (2007-04-21) me
# - added logging of status for use with &INetSim::Report::GenReport()
#
# Version 0.1   (2007-04-09) th
# - initial version
#
#############################################################
