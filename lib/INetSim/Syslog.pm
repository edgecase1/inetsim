# -*- perl -*-
#
# INetSim::Syslog - A fake Syslog server
#
# RFC 3164 - The BSD syslog Protocol
#
# (c)2008-2010 Matthias Eckert, Thomas Hungenberg
#
# Version 0.3    (2010-04-12)
#
# For history/changelog see bottom of this file.
#
#############################################################

package INetSim::Syslog;

use strict;
use warnings;
use base qw(INetSim::GenericServer);


my %Facility = (	 0	=>	'kernel',
			 1	=>	'user',
			 2	=>	'mail',
			 3	=>	'system',
			 4	=>	'security/authorization',
			 5	=>	'syslog',
			 6	=>	'printer',
			 7	=>	'news',
			 8	=>	'uucp',
			 9	=>	'clock',
			10	=>	'security/authorization',
			11	=>	'ftp',
			12	=>	'ntp',
			13	=>	'log audit',
			14	=>	'log alert',
			15	=>	'clock',
			16	=>	'local0',
			17	=>	'local1',
			18	=>	'local2',
			19	=>	'local3',
			20	=>	'local4',
			21	=>	'local5',
			22	=>	'local6',
			23	=>	'local7'
);


my %Severity = (	0	=>	'emergency',
			1	=>	'alert',
			2	=>	'critical',
			3	=>	'error',
			4	=>	'warning',
			5	=>	'notice',
			6	=>	'informational',
			7	=>	'debug'
);


sub configure_hook {
    my $self = shift;
    my $server = $self->{server};

    $server->{host}   = &INetSim::Config::getConfigParameter("Default_BindAddress"); # bind to address
    $server->{port}   = &INetSim::Config::getConfigParameter("Syslog_BindPort");  # bind to port
    $server->{proto}  = 'udp';                              # UDP protocol
    $server->{user}   = &INetSim::Config::getConfigParameter("Default_RunAsUser");       # user to run as
    $server->{group}  = &INetSim::Config::getConfigParameter("Default_RunAsGroup");    # group to run as
    $server->{setsid} = 0;                                  # do not daemonize
    $server->{no_client_stdout} = 1;                        # do not attach client to STDOUT
    $server->{log_level} = 0;                               # do not log anything
    $server->{udp_recv_len} = 960;                          # default is 4096
}


sub pre_loop_hook {
    $0 = 'inetsim_' . &INetSim::Config::getConfigParameter("Syslog_ServiceName");
    &INetSim::Log::MainLog("started (PID $$)", &INetSim::Config::getConfigParameter("Syslog_ServiceName"));
}


sub pre_server_close_hook {
    &INetSim::Log::MainLog("stopped (PID $$)", &INetSim::Config::getConfigParameter("Syslog_ServiceName"));
}


sub fatal_hook {
    &INetSim::Log::MainLog("failed!", &INetSim::Config::getConfigParameter("Syslog_ServiceName"));
    exit 0;
}


sub process_request {
    my $self = shift;
    my $server = $self->{server};
    my $client = $server->{client};
    my $rhost = $server->{peeraddr};
    my $rport = $server->{peerport};
    my $serviceName = &INetSim::Config::getConfigParameter("Syslog_ServiceName");
    my $maxchilds = &INetSim::Config::getConfigParameter("Default_MaxChilds");
    my $trim_maxlength = &INetSim::Config::getConfigParameter("Syslog_TrimMaxLength");
    my $accept_invalid = &INetSim::Config::getConfigParameter("Syslog_AcceptInvalid");

    my $stat_success = 0;

    my $msg;
    my $priority;
    my $timestamp;
    my $content;
    my $facility;
    my $severity;
    my $length;
    my $valid = 0;
    my $relay = 0;
    my $hostname;
    my $header;
    my $message;


    if ($server->{numchilds} >= $maxchilds) {
	print $client "Maximum number of connections ($maxchilds) exceeded.\n";
	&INetSim::Log::SubLog("[$rhost:$rport] Connection refused - maximum number of connections ($maxchilds) exceeded.", $serviceName, $$);
    }
    else {
	&INetSim::Log::SubLog("[$rhost:$rport] connect", $serviceName, $$);

 	$msg = $server->{udp_data};	
	chomp($msg);
	$msg =~ s/^[\r\n\s\t]+//;
	$msg =~ s/[\r\n\s\t]+$//;
	
	if (! $msg) {
            &INetSim::Log::SubLog("[$rhost:$rport] recv: invalid syslog packet (empty)", $serviceName, $$);
            &INetSim::Log::SubLog("[$rhost:$rport] disconnect", $serviceName, $$);
	    return;
	}
	
        if ($trim_maxlength && length($msg) > 1024) {
            $msg = substr($msg, 0, 1024);
	    &INetSim::Log::SubLog("[$rhost:$rport] info: Shortened syslog packet to maximum length of 1024 bytes", $serviceName, $$);
        }
	
	# check for valid priority and timestamp field
	if ($msg =~ /^\<([\d]{1,3})\>((Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[\s]+[\d]{1,2}[\s]+\d\d:\d\d:\d\d)[\s]+(.*)$/) {
	    if (defined ($1) && length($1) && defined ($2) && length($2) && defined ($4) && length($4)) {
	        $priority = $1;
		$timestamp = $2;
		$content = $4;
		$length = int(length($priority) + 2 + length($timestamp) + 1 + length($content));
		($facility, $severity) = &dec_PRIORITY($priority);
		if (defined ($facility) && defined ($severity)) {
		    if ($trim_maxlength && $length > 1024) {
		        $content = substr($content, 0, int($length - ($length - 1024)));
			&INetSim::Log::SubLog("[$rhost:$rport] info: Shortened syslog packet to maximum length of 1024 bytes", $serviceName, $$);
		    }
		    $valid = 1;
		}
	    }
	}
	elsif ($msg =~ /^\<([\d]{1,3})\>(.*)$/) {
	    if (defined ($1) && length($1) && defined ($2) && length($2)) {
	        $priority = $1;
		$timestamp = &_timestamp;
		$content = $2;
		$length = int(length($priority) + 2 + length($content));
		($facility, $severity) = &dec_PRIORITY($priority);
		if (defined ($facility) && defined ($severity)) {
		    if ($trim_maxlength && $length > 1024) {
		        $content = substr($content, 0, int($length - ($length - 1024)));
			&INetSim::Log::SubLog("[$rhost:$rport] info: Shortened syslog packet to maximum length of 1024 bytes", $serviceName, $$);
		    }
		    $valid = 1;
		}
	    }
	}
	
	# build priority, timestamp and hostname for the packet
	if (! $valid && $accept_invalid) {
	    $priority = 13;
	    $timestamp = &_timestamp;
	    $content = $msg;
	    $length = int(length($priority) + 2 + length($timestamp) + 1 + length($content));
	    ($facility, $severity) = &dec_PRIORITY($priority);
	    if (defined ($facility) && defined ($severity)) {
		if ($trim_maxlength && $length > 1024) {
		    $content = substr($content, 0, int($length - ($length - 1024)));
		    &INetSim::Log::SubLog("[$rhost:$rport] info: Shortened syslog packet to maximum length of 1024 bytes", $serviceName, $$);
		}
		$valid = 1;
		$relay = 1;
	    }
	}
	
	# now log the "decoded" message
	if ($valid) {
	    if ($accept_invalid && $relay) {
	        &INetSim::Log::SubLog("[$rhost:$rport] recv: [Relayed] $facility.$severity  $timestamp  $content", $serviceName, $$);
	    }
	    else {
	        &INetSim::Log::SubLog("[$rhost:$rport] recv: $facility.$severity  $timestamp  $content", $serviceName, $$);
	    }
	    $stat_success = 1;
	}
	else {
	    &INetSim::Log::SubLog("[$rhost:$rport] recv: invalid syslog packet", $serviceName, $$);
	}
	&INetSim::Log::SubLog("[$rhost:$rport] disconnect", $serviceName, $$);
    }

    if ($stat_success == 1) {
        &INetSim::Log::SubLog("[$rhost:$rport] stat: $stat_success facility=$facility severity=$severity", $serviceName, $$);
    }
    else {
        &INetSim::Log::SubLog("[$rhost:$rport] stat: $stat_success", $serviceName, $$);
    }
}


sub _timestamp {
    my @months = qw/Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec/;
    my ($sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst) = localtime(&INetSim::FakeTime::get_faketime());

    $year += 1900;

    return (sprintf("%3s %2s %02d:%02d:%02d", $months[$mon], $mday, $hour, $min, $sec));
}


sub dec_PRIORITY {
    my $pri = shift;
    my $fac;
    my $sev;

    if (defined ($pri) && length($pri) && $pri =~ /^[\d]{1,3}$/ && $pri >= 0 && $pri <= 191 && $pri ne "00" && $pri ne "000") {
        $fac = ($pri & 248) >> 3;
        $sev = $pri & 7;
	return ($Facility{$fac}, $Severity{$sev});
    }
    return undef;
}


1;
#############################################################
#
# History:
#
# Version 0.3   (2010-04-12) me
# - do not filter non-printable characters because it's already
#   implemented in the log module
#
# Version 0.2   (2008-09-08) me
# - changed syslog format because of messages without timestamp
#
# Version 0.1   (2008-09-08) me
# - initial version
#
#############################################################
