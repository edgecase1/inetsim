# -*- perl -*-
#
# INetSim::Dummy::UDP - A dummy UDP server
#
# (c)2008-2010 Matthias Eckert, Thomas Hungenberg
#
# Version 0.4  (2010-04-12)
#
# For history/changelog see bottom of this file.
#
#############################################################

package INetSim::Dummy::UDP;

use strict;
use warnings;
use base qw(INetSim::Dummy);



sub configure_hook {
    my $self = shift;

    $self->{server}->{host}   = &INetSim::Config::getConfigParameter("Default_BindAddress"); # bind to address
    $self->{server}->{port}   = &INetSim::Config::getConfigParameter("Dummy_UDP_BindPort");  # bind to port
    $self->{server}->{proto}  = 'udp';                                   # UDP protocol
    $self->{server}->{user}   = &INetSim::Config::getConfigParameter("Default_RunAsUser");       # user to run as
    $self->{server}->{group}  = &INetSim::Config::getConfigParameter("Default_RunAsGroup");    # group to run as
    $self->{server}->{setsid} = 0;                                       # do not daemonize
    $self->{server}->{no_client_stdout} = 1;                             # do not attach client to STDOUT
    $self->{server}->{log_level} = 0;                                    # do not log anything
#    $self->{server}->{udp_recv_len} = 1024;                              # default is 4096

    $self->{servicename} = &INetSim::Config::getConfigParameter("Dummy_UDP_ServiceName");
    $self->{max_childs} = &INetSim::Config::getConfigParameter("Default_MaxChilds");
}



sub pre_loop_hook {
    my $self = shift;

    $0 = "inetsim_$self->{servicename}";
    &INetSim::Log::MainLog("started (PID $$)", $self->{servicename});
}



sub pre_server_close_hook {
    my $self = shift;

    &INetSim::Log::MainLog("stopped (PID $$)", $self->{servicename});
}



sub fatal_hook {
    my $self = shift;

    &INetSim::Log::MainLog("failed!", $self->{servicename});
    exit 0;
}



sub process_request {
    my $self = shift;
    my $client = $self->{server}->{client};
    my $rhost = $self->{server}->{peeraddr};
    my $rport = $self->{server}->{peerport};
    my $stat_success = 0;

    &INetSim::Log::SubLog("[$rhost:$rport] connect", $self->{servicename}, $$);
    if ($self->{server}->{numchilds} >= $self->{max_childs}) {
        print $client "Maximum number of connections ($self->{max_childs}) exceeded.\n";
        &INetSim::Log::SubLog("[$rhost:$rport] Connection refused - maximum number of connections ($self->{max_childs}) exceeded.", $self->{servicename}, $$);
    }
    else {
        my $recvmsg = $self->{server}->{udp_data};
        $recvmsg =~ s/^[\r\n]+//g;
        $recvmsg =~ s/[\r\n]+$//g;
        if ($recvmsg ne "") {
            &INetSim::Log::SubLog("[$rhost:$rport] recv: " . $recvmsg, $self->{servicename}, $$);
            $stat_success = 1;
        }
    }
    &INetSim::Log::SubLog("[$rhost:$rport] disconnect", $self->{servicename}, $$);
    &INetSim::Log::SubLog("[$rhost:$rport] stat: $stat_success", $self->{servicename}, $$);
}



1;
#############################################################
#
# History:
#
# Version 0.4   (2010-04-12) me
# - do not filter non-printable characters because it's already
#   implemented in the log module
#
# Version 0.3   (2009-10-28) me
# - improved some code parts
# - added logging of status
#
# Version 0.2   (2008-08-27) me
# - added logging of process id
#
# Version 0.1   (2008-03-06) me
# - initial version
#
#############################################################
