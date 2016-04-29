# -*- perl -*-
#
# INetSim::Finger - A fake Finger server
#
# RFC 1288 - Finger User Information Protocol
#
# (c)2007-2010 Matthias Eckert, Thomas Hungenberg
#
# Version 0.16  (2010-04-12)
#
# For history/changelog see bottom of this file.
#
#############################################################

package INetSim::Finger;

use strict;
use warnings;
use base qw(INetSim::GenericServer);


my @DATA;
my $LASTREAD = 0;



sub configure_hook {
    my $self = shift;

    $self->{server}->{host}   = &INetSim::Config::getConfigParameter("Default_BindAddress"); # bind to address
    $self->{server}->{proto}  = 'tcp';                                      # TCP protocol
    $self->{server}->{user}   = &INetSim::Config::getConfigParameter("Default_RunAsUser");       # user to run as
    $self->{server}->{group}  = &INetSim::Config::getConfigParameter("Default_RunAsGroup");    # group to run as
    $self->{server}->{setsid} = 0;                                    # do not daemonize
    $self->{server}->{no_client_stdout} = 1;                          # do not attach client to STDOUT
    $self->{server}->{log_level} = 0;                                 # do not log anything
    $self->{server}->{port}   = &INetSim::Config::getConfigParameter("Finger_BindPort");  # bind to port
    # service name
    $self->{servicename} = &INetSim::Config::getConfigParameter("Finger_ServiceName");
    # timeout
    $self->{timeout} = &INetSim::Config::getConfigParameter("Default_TimeOut");
    # max childs
    $self->{maxchilds} = &INetSim::Config::getConfigParameter("Default_MaxChilds");
}



sub pre_loop_hook {
    my $self = shift;

    $0 = 'inetsim_' . $self->{servicename};
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
    my $query;
    my @token;
    my $username;
    my $lasthop;
    my @dummy;

    if ($self->{server}->{numchilds} >= $self->{maxchilds}) {
	print $client "Maximum number of connections ($self->{maxchilds}) exceeded.\n";
	&INetSim::Log::SubLog("[$rhost:$rport] Connection refused - maximum number of connections ($self->{maxchilds}) exceeded.", $self->{servicename}, $$);
    }
    else {
        eval {
            local $SIG{'ALRM'} = sub { die "TIMEOUT" };
            alarm($self->{timeout});
	    &INetSim::Log::SubLog("[$rhost:$rport] connect", $self->{servicename}, $$);
	    while ($query = <$client>){
	        alarm($self->{timeout});
                if (defined ($query)) {
                    $query =~ s/^[\r\n\s\t]+//g;
                    $query =~ s/[\r\n\s\t]+$//g;
                    # remove '/W' strings
                    $query =~ s/\/W//g;
                    &INetSim::Log::SubLog("[$rhost:$rport] recv: ".$query, $self->{servicename}, $$);
                    &read_data_files(&INetSim::Config::getConfigParameter("Finger_DataDirName"));
                    # restricted charset (my decision)
                    if ($query && $query =~ /([^a-zA-Z0-9\-\_\@\.\s\t])/) {
                        print $client "Your request contains illegal characters.\r\n";
                        &INetSim::Log::SubLog("[$rhost:$rport] send: Your request contains illegal characters.", $self->{servicename}, $$);
                        last;
                    }
                    $query =~ s/[\t\s]+/\ /g;
                    if ($query =~ /^$/) {
                        foreach (@DATA) {
                            if (/^\=\=\=/) {
                                print $client "\r\n";
                                &INetSim::Log::SubLog("[$rhost:$rport] send: ", $self->{servicename}, $$);
                            }
                            else {
                                print $client "$_\r\n";
                                &INetSim::Log::SubLog("[$rhost:$rport] send: $_", $self->{servicename}, $$);
                            }
                        }
                        $stat_success = 1;
                        last;
                    }
                    else {
                        if ($query =~ /^.+$/) {
                            @token = ();
                            @token = split(/\@/, $query);
                            if ($token[0]) {
                                $username = $token[0];
                                $username =~ s/[\s]+//g;
                            }
                            if (@token >= 2) {
                                $lasthop = pop(@token);
                                $lasthop =~ s/[\s]+//g;
                            }
                            if ($username) {
                                @dummy = ();
                                @dummy = &search_name($username);
                                if (@dummy) {
                                    if ($lasthop) {
                                        print $client "[$lasthop]\r\n";
                                        &INetSim::Log::SubLog("[$rhost:$rport] send: [$lasthop]", $self->{servicename}, $$);
                                    }
                                    foreach (@dummy) {
                                        print $client "$_\r\n";
                                        &INetSim::Log::SubLog("[$rhost:$rport] send: $_", $self->{servicename}, $$);
                                    }
                                    $stat_success = 1;
                                    last;
                                }
                                else {
                                    if ($lasthop) {
                                        print $client "[$lasthop]\r\n";
                                        &INetSim::Log::SubLog("[$rhost:$rport] send: [$lasthop]", $self->{servicename}, $$);
                                    }
                                    print $client "finger: $username: no such user.\r\n";
                                    &INetSim::Log::SubLog("[$rhost:$rport] send: finger: $username: no such user.", $self->{servicename}, $$);
                                    last;
                                }
                            }
                            else {
                                if ($lasthop) {
                                    print $client "[$lasthop]\r\n";
                                    &INetSim::Log::SubLog("[$rhost:$rport] send: [$lasthop]", $self->{servicename}, $$);
                                    foreach (@DATA) {
                                        if (/^\=\=\=/) {
                                            print $client "\r\n";
                                            &INetSim::Log::SubLog("[$rhost:$rport] send: ", $self->{servicename}, $$);
                                        }
                                        else {
                                            print $client "$_\r\n";
                                            &INetSim::Log::SubLog("[$rhost:$rport] send: $_", $self->{servicename}, $$);
                                        }
                                    }
                                    $stat_success = 1;
                                    last;
                                }
                                else {
                                    print $client "finger: $query: no such user.\r\n";
                                    &INetSim::Log::SubLog("[$rhost:$rport] send: finger: $query: no such user.", $self->{servicename}, $$);
                                    last;
                                }
                            }
                        }
                        last;
                    }
                    last;
                }
                else {
                    print $client "finger: $query: no such user.\r\n";
                    &INetSim::Log::SubLog("[$rhost:$rport] send: finger: $query: no such user.", $self->{servicename}, $$);
                    last;
                }
                last;
	    }
            alarm(0);
        };
        if ($@ =~ /TIMEOUT/) {
            &INetSim::Log::SubLog("[$rhost:$rport] disconnect (timeout)", $self->{servicename}, $$);
        }
        else {
            &INetSim::Log::SubLog("[$rhost:$rport] disconnect", $self->{servicename}, $$);
        }
    }
    &INetSim::Log::SubLog("[$rhost:$rport] stat: $stat_success", $self->{servicename}, $$);
}



sub search_name {
    my $name = shift;
    my @tmp = ();
    my $match = 0;
    my $count = 0;

    foreach (@DATA) {
        if (/^\=\=\=/) {
            $match = 0;
        }
        if (m/^(Login.*?)(\s($name)\b)/i) {
            if ($count) {
                push (@tmp, "");
            }
            push (@tmp, $_);
            $match = 1;
            $count++;
            next;
        }
        if ($match) {
            push (@tmp, $_);
        }
    }

    return (@tmp);
}



sub datetime {
    my $now = &INetSim::FakeTime::get_faketime();
    my $delta = int(rand(3600) + 1);

    return (localtime ($now - $delta));
}



sub tty {
    my %prefix = ( 0 => "tty", 1 => "pty", 2 => "pts/", 3 => "ttyp");

    return ($prefix{int(rand(3))} . int(rand(6)));
}



sub shell {
    my %prefix = ( 0 => "/bin/sh", 1 => "/bin/bash", 2 => "/bin/zsh", 3 => "/bin/ksh");

    return ($prefix{int(rand(3))});
}



sub read_data_files {
    my $dir = shift;
    my @files;
    my @raw;
    my $content;
    my $time;
    my $tty;
    my $shell;
    my $now = &INetSim::FakeTime::get_faketime();
    my $diff = $now - $LASTREAD;

    if ($diff > 60) {
        if (-d $dir) {
            chomp(@files=<$dir/*.finger>);
            if (@files) {
                foreach (@files) {
                    next if (/^#/);
                    if (open (FH, $_)) {
                        chomp(@raw=<FH>);
                        close FH;
                        foreach (@raw) {
                            next if (/^\#/);
                            s/[\r\n]+$//g;
                            if (/\{DATETIME\}/) {
                                $time = &datetime;
                                s/\{DATETIME\}/$time/g;
                            }
                            if (/\{TTY\}/) {
                                $tty = &tty;
                                s/\{TTY\}/$tty/g;
                            }
                            if (/\{SHELL\}/) {
                                $shell = &shell;
                                s/\{SHELL\}/$shell/g;
                            }
                            push (@DATA, $_);
                        }
                    }
                }
            }
        }
        if (! @DATA) {
            push (@DATA, "Login: devel                            Name: Developer");
            push (@DATA, "Directory: /home/devel                  Shell: /bin/bash");
            push (@DATA, "Never logged in.");
            push (@DATA, "No mail.");
            push (@DATA, "No Plan.");
        }
    }
    $LASTREAD = $now;
}



1;
#############################################################
#
# History:
#
# Version 0.16   (2010-04-12) me
# - do not filter non-printable characters because it's already
#   implemented in the log module
# - some small changes
#
# Version 0.15   (2008-08-27) me
# - added logging of process id
#
# Version 0.14   (2008-03-25) me
# - added timeout after inactivity of n seconds, using new
#   config parameter Default_TimeOut
#
# Version 0.13 (2007-12-31) th
# - change process name
#
# Version 0.12 (2007-12-07) me
# - query charset restricted
# - added a check for 'illegal' chars
# - changed the regex in function 'search_name'
# - removed unused variables
# - removed some typos
#
# Version 0.11 (2007-11-09) me
# - added functions 'datetime', 'tty' and 'shell' for dynamic content
#   generation
# - changed function 'read_data_files' for work with variables in data files
# - added an example data file entry with new variables DATETIME, TTY
#   and SHELL
#
# Version 0.1  (2007-11-07) me
# - initial version with static content
#
#############################################################
