# -*- perl -*-
#
# INetSim::Ident - A fake Ident server
#
# RFC 1413 - Identification Protocol
#
# (c)2007-2009 Matthias Eckert, Thomas Hungenberg
#
# Version 0.47  (2009-10-30)
#
# For history/changelog see bottom of this file.
#
#############################################################

package INetSim::Ident;

use strict;
use warnings;
use base qw(INetSim::GenericServer);

my %LPORT = ( 7		=> "inetd",
              9		=> "inetd",
              13	=> "inetd",
              17	=> "inetd",
              19	=> "inetd",
              20	=> "ftp",
              21	=> "ftp",
              25	=> "postfix",
              37	=> "inetd",
              53	=> "named",
              80	=> "www-data",
              113	=> "identd",
              443	=> "www-data",
              515	=> "lpr",
              8080	=> "proxy"
);



sub configure_hook {
    my $self = shift;

    $self->{server}->{host}   = &INetSim::Config::getConfigParameter("Default_BindAddress"); # bind to address
    $self->{server}->{port}   = &INetSim::Config::getConfigParameter("Ident_BindPort");  # bind to port
    $self->{server}->{proto}  = 'tcp';                                      # TCP protocol
    $self->{server}->{user}   = &INetSim::Config::getConfigParameter("Default_RunAsUser");       # user to run as
    $self->{server}->{group}  = &INetSim::Config::getConfigParameter("Default_RunAsGroup");    # group to run as
    $self->{server}->{setsid} = 0;                                    # do not daemonize
    $self->{server}->{no_client_stdout} = 1;                          # do not attach client to STDOUT
    $self->{server}->{log_level} = 0;                                 # do not log anything

    $self->{servicename} = &INetSim::Config::getConfigParameter("Ident_ServiceName");
    $self->{max_childs} = &INetSim::Config::getConfigParameter("Default_MaxChilds");
    $self->{timeout} = &INetSim::Config::getConfigParameter("Default_TimeOut");
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
    my ($s_port, $c_port);

    &INetSim::Log::SubLog("[$rhost:$rport] connect", $self->{servicename}, $$);
    if ($self->{server}->{numchilds} >= $self->{max_childs}) {
        print $client "Maximum number of connections ($self->{max_childs}) exceeded.\n";
        &INetSim::Log::SubLog("[$rhost:$rport] Connection refused - maximum number of connections ($self->{max_childs}) exceeded.", $self->{servicename}, $$);
    }
    else {
        eval {
            local $SIG{'ALRM'} = sub { die "TIMEOUT" };
            alarm($self->{timeout});
            while (my $line = <$client>){
                $line =~ s/[\r\n]+$//g;
                $line =~ s/[\s\t]+//g;
                alarm($self->{timeout});
                &INetSim::Log::SubLog("[$rhost:$rport] recv: ".$line, $self->{servicename}, $$);
                if ($line =~ /^\d{1,5}\,\d{1,5}\z/) {
                    ($s_port, $c_port) = split(/\,/, $line);
                    if ($s_port >= 1 && $s_port <= 65535 && $c_port >= 1 && $c_port <= 65535) {
                        my $out;
                        if (defined $LPORT{$s_port} && $LPORT{$s_port}) {
                            $out = "$s_port , $c_port : USERID : UNIX : $LPORT{$s_port}";
                        }
                        elsif ($s_port <= 1024) {
                            $out = "$s_port , $c_port : USERID : UNIX : root";
                        }
                        else {
                            $out = "$s_port , $c_port : USERID : UNIX : nobody";
                        }
                        print $client "$out\r\n";
                        &INetSim::Log::SubLog("[$rhost:$rport] send: $out", $self->{servicename}, $$);
                        $stat_success = 1;
                    }
                    else {
                        print $client "$s_port , $c_port : ERROR : INVALID-PORT\r\n";
                        &INetSim::Log::SubLog("[$rhost:$rport] send: $s_port , $c_port : ERROR : INVALID-PORT", $self->{servicename}, $$);
                    }
                }
                elsif ($line =~ /^QUIT$/i) {
                    last;
                }
                else {
                    print $client "0 , 0 : ERROR : UNKNOWN-ERROR\r\n";
                    &INetSim::Log::SubLog("[$rhost:$rport] send: 0 , 0 : ERROR : UNKNOWN-ERROR", $self->{servicename}, $$);
                    last;
                }
                alarm($self->{timeout});
            }
            alarm(0);
        };
    }
    if ($@ =~ /TIMEOUT/) {
        &INetSim::Log::SubLog("[$rhost:$rport] disconnect (timeout)", $self->{servicename}, $$);
    }
    else {
        &INetSim::Log::SubLog("[$rhost:$rport] disconnect", $self->{servicename}, $$);
    }
    if ($stat_success == 1) {
        &INetSim::Log::SubLog("[$rhost:$rport] stat: $stat_success lport=$s_port rport=$c_port", $self->{servicename}, $$);
    }
    else {
        &INetSim::Log::SubLog("[$rhost:$rport] stat: $stat_success", $self->{servicename}, $$);
    }
}



1;
#############################################################
#
# History:
#
# Version 0.47   (2009-10-30) me
# - improved some code parts
#
# Version 0.46   (2008-08-27) me
# - added logging of process id
#
# Version 0.45   (2008-03-25) me
# - changed timeout handling
#
# Version 0.44   (2008-03-19) me
# - added timeout after inactivity of n seconds, using new
#   config parameter Default_TimeOut
#
# Version 0.43  (2007-12-31) th
# - change process name
#
# Version 0.42  (2007-05-08) th
# - replace non-printable characters with "." in recvmsg
#
# Version 0.41  (2007-04-26) th
# - use getConfigParameter
#
# Version 0.4   (2007-04-21) me
# - small bugfixes with variables
# - added handling of quit
# - added logging of status for use with &INetSim::Report::GenReport()
#
# Version 0.3   (2007-04-19) me
# - changed check for MaxChilds, BindAddress, RunAsUser and
#   RunAsGroup
#
# Version 0.2   (2007-03-27) th
# - rewrote module to use INetSim::GenericServer
#
# Version 0.11  (2007-03-19) th
# - fixed problem with uninitialized value of $recvmsg
#
# Version 0.1   (2007-03-18) me
#
#############################################################
