# -*- perl -*-
#
# INetSim::DNS - A fake DNS server
#
# RFC 1035 (and many others) - Domain Name System
#
# (c)2007-2010 Matthias Eckert, Thomas Hungenberg
#
# Version 0.46   (2010-09-18)
#
# For history/changelog see bottom of this file.
#
#############################################################

package INetSim::DNS;

use strict;
use warnings;
use Net::DNS;
use Net::DNS::Nameserver;


sub dns{
    # check for broken version 0.65 of Net::DNS
    if ($Net::DNS::VERSION eq "0.65") {
	&INetSim::Log::MainLog("failed! (The installed version 0.65 of Perl library Net::DNS is broken. Please upgrade to version 0.66 or later.)", &INetSim::Config::getConfigParameter("DNS_ServiceName"));
	exit 1;
    }

    my $CPID = $$;
    my $localaddr = (defined &INetSim::Config::getConfigParameter("DNS_BindAddress") ? &INetSim::Config::getConfigParameter("DNS_BindAddress") : &INetSim::Config::getConfigParameter("Default_BindAddress"));
    $localaddr =~ /^(.*)$/;  # fool taint check
    $localaddr = $1;
    local $SIG{'INT'} = 'IGNORE';
    local $SIG{'TERM'} = sub {&INetSim::Log::MainLog("stopped (PID $CPID)", &INetSim::Config::getConfigParameter("DNS_ServiceName")); exit 0;};

    my $server = Net::DNS::Nameserver->new(LocalAddr    => $localaddr,
					   LocalPort    => &INetSim::Config::getConfigParameter("DNS_BindPort"),
					   ReplyHandler => \&dns_reply_handler,
					   Verbose      => '0');
    if(! $server) {
	&INetSim::Log::MainLog("failed!", &INetSim::Config::getConfigParameter("DNS_ServiceName"));
	exit 1;
    }

    # drop root privileges
    my $runasuser = (defined &INetSim::Config::getConfigParameter("DNS_RunAsUser") ? &INetSim::Config::getConfigParameter("DNS_RunAsUser") : &INetSim::Config::getConfigParameter("Default_RunAsUser"));
    my $runasgroup = (defined &INetSim::Config::getConfigParameter("DNS_RunAsGroup") ? &INetSim::Config::getConfigParameter("DNS_RunAsGroup") : &INetSim::Config::getConfigParameter("Default_RunAsGroup"));

    my $uid = getpwnam($runasuser);
    my $gid = getgrnam($runasgroup);
    POSIX::setgid($gid);
    my $newgid = POSIX::getgid();
    if ($newgid != $gid) {
	&INetSim::Log::MainLog("failed! (Cannot switch group)", &INetSim::Config::getConfigParameter("DNS_ServiceName"));
	exit 0;
    }

    POSIX::setuid($uid);
    if ($< != $uid || $> != $uid) {
	$< = $> = $uid; # try again - reportedly needed by some Perl 5.8.0 Linux systems
	if ($< != $uid) {
	    &INetSim::Log::MainLog("failed! (Cannot switch user)", &INetSim::Config::getConfigParameter("DNS_ServiceName"));
	    exit 0;
	}
    }

    $0 = 'inetsim_' . &INetSim::Config::getConfigParameter("DNS_ServiceName");
    &INetSim::Log::MainLog("started (PID $CPID)", &INetSim::Config::getConfigParameter("DNS_ServiceName"));
    $server->main_loop;
    &INetSim::Log::MainLog("stopped (PID $CPID)", &INetSim::Config::getConfigParameter("DNS_ServiceName"));
    exit 0;
}


sub dns_reply_handler {
# Ist noch Baustelle !!!!
    my ($queryname, $queryclass, $querytype, $rhost, $query) = @_;
    my (@ans, @auth, @add) = ();
    my @logans = ();
    my $resultcode = "REFUSED";
    my $ttl = 3600;
    my $SOA_serial = 20070301;
    my $SOA_refresh = 1000;
    my $SOA_retry = 800;
    my $SOA_expire = 7200;
    my $SOA_minimum = 3600;
    my $stat_success = 0;
    my $serviceName = &INetSim::Config::getConfigParameter("DNS_ServiceName");
    my $localaddress = &INetSim::Config::getConfigParameter("Default_BindAddress");

    &INetSim::Log::SubLog("[$rhost] connect", $serviceName, $$);

    if (! defined ($queryname) || ! defined ($queryclass) || ! defined ($querytype) || ! defined ($rhost)) {
        $resultcode = "SERVFAIL";
    }
    
    elsif ($querytype eq "A") {
	my $rdata;
	if ($queryname =~ /^wpad$/i  || $queryname =~ /^wpad\..*/i) {
	    $rdata = $localaddress;
	}
	else {
	    $rdata = &getIP($queryname);
	}
	push @ans, Net::DNS::RR->new("$queryname $ttl $queryclass A $rdata");
	push (@logans, "$queryname $ttl $queryclass A $rdata");
	$resultcode = "NOERROR";
    }

    elsif ($querytype eq "SOA") {
	# Answer section
	push @ans, Net::DNS::RR->new("$queryname $ttl $queryclass SOA ns1.$queryname hostmaster.$queryname $SOA_serial $SOA_refresh $SOA_retry $SOA_expire $SOA_minimum");
	push @logans, "$queryname $ttl $queryclass SOA ns1.$queryname hostmaster.$queryname $SOA_serial $SOA_refresh $SOA_retry $SOA_expire $SOA_minimum";
	# NS in Authority section
	push @auth, Net::DNS::RR->new("$queryname $ttl $queryclass NS ns1.$queryname");
	push @auth, Net::DNS::RR->new("$queryname $ttl $queryclass NS ns2.$queryname");
	push @logans, "$queryname $ttl $queryclass NS ns1.$queryname";
	push @logans, "$queryname $ttl $queryclass NS ns2.$queryname";
	# IP-Adressen für NS in Additional section
	my $ns1ip = getIP("ns1.$queryname");
	my $ns2ip = getIP("ns2.$queryname");
	push @add, Net::DNS::RR->new("ns1.$queryname $ttl $queryclass A $ns1ip");
	push @add, Net::DNS::RR->new("ns2.$queryname $ttl $queryclass A $ns2ip");
	push @logans, "ns1.$queryname $ttl $queryclass A $ns1ip";
	push @logans, "ns2.$queryname $ttl $queryclass A $ns2ip";
	$resultcode = "NOERROR";
    }

    elsif ($querytype eq "PTR") {
	my $rdata = &getHost($queryname);
	push @ans, Net::DNS::RR->new("$queryname $ttl $queryclass PTR $rdata");
	push @logans, "$queryname $ttl $queryclass $querytype $rdata";
	$resultcode = "NOERROR";
    }

    elsif ($querytype eq "TXT") {
        my $rdata;
        # http://www.ietf.org/rfc/rfc4892.txt
        # http://www.ietf.org/proceedings/54/I-D/draft-ietf-dnsop-serverid-00.txt
        if ($queryclass eq "CH" && ($queryname =~ /^(version|hostname)\.bind/i || $queryname =~ /^(id|version)\.server/i)) {
            $rdata = &INetSim::Config::getConfigParameter("DNS_Version");
        }
        else {
            $rdata = "foobar";
        }
        push @ans, Net::DNS::RR->new("$queryname $ttl $queryclass TXT \"$rdata\"");
        push @logans, "$queryname $ttl $queryclass $querytype \"$rdata\"";
        $resultcode = "NOERROR";
    }

    elsif ($querytype eq "MX") {
	push @ans, Net::DNS::RR->new("$queryname $ttl $queryclass MX 10 mx1.$queryname");
	push @ans, Net::DNS::RR->new("$queryname $ttl $queryclass MX 20 mx2.$queryname");
	push (@logans, "$queryname $ttl $queryclass MX 10 mx1.$queryname");
	push (@logans, "$queryname $ttl $queryclass MX 20 mx2.$queryname");
	# IP-Adressen für MX in Additional Section
	my $mx1ip = getIP("mx1.$queryname");
	my $mx2ip = getIP("mx2.$queryname");
	push @add, Net::DNS::RR->new("mx1.$queryname $ttl $queryclass A $mx1ip");
	push @add, Net::DNS::RR->new("mx2.$queryname $ttl $queryclass A $mx2ip");
	push (@logans, "mx1.$queryname $ttl $queryclass A $mx1ip");
	push (@logans, "mx2.$queryname $ttl $queryclass A $mx2ip");
	$resultcode = "NOERROR";
    }

    elsif ($querytype eq "NS") {
	push @ans, Net::DNS::RR->new("$queryname $ttl $queryclass NS ns1.$queryname");
	push @ans, Net::DNS::RR->new("$queryname $ttl $queryclass NS ns2.$queryname");
	push (@logans, "$queryname $ttl $queryclass NS ns1.$queryname");
	push (@logans, "$queryname $ttl $queryclass NS ns2.$queryname");
	# IP-Adressen für NS in Additional Section
	my $ns1ip = getIP("ns1.$queryname");
	my $ns2ip = getIP("ns2.$queryname");
	push @add, Net::DNS::RR->new("ns1.$queryname $ttl $queryclass A $ns1ip");
	push @add, Net::DNS::RR->new("ns2.$queryname $ttl $queryclass A $ns2ip");
	push @logans, "ns1.$queryname $ttl $queryclass A $ns1ip";
	push @logans, "ns2.$queryname $ttl $queryclass A $ns2ip";
	$resultcode = "NOERROR";
    }

    elsif ($querytype eq "ANY") {
	# SOA
	push @ans, Net::DNS::RR->new("$queryname $ttl $queryclass SOA ns1.$queryname hostmaster.$queryname $SOA_serial $SOA_refresh $SOA_retry $SOA_expire $SOA_minimum");
	push @logans, "$queryname $ttl $queryclass SOA ns1.$queryname hostmaster.$queryname $SOA_serial $SOA_refresh $SOA_retry $SOA_expire $SOA_minimum";
	# Nameserver
	push @ans, Net::DNS::RR->new("$queryname $ttl $queryclass NS ns1.$queryname");
	push @ans, Net::DNS::RR->new("$queryname $ttl $queryclass NS ns2.$queryname");
	push (@logans, "$queryname $ttl $queryclass NS ns1.$queryname");
	push (@logans, "$queryname $ttl $queryclass NS ns2.$queryname");
	# Mailserver
	push @ans, Net::DNS::RR->new("$queryname $ttl $queryclass MX 10 mx1.$queryname");
	push @ans, Net::DNS::RR->new("$queryname $ttl $queryclass MX 20 mx2.$queryname");
	push (@logans, "$queryname $ttl $queryclass $querytype 10 mx1.$queryname");
	push (@logans, "$queryname $ttl $queryclass $querytype 20 mx2.$queryname");
	# A Record
	my $rdata = &getIP($queryname);
	push @ans, Net::DNS::RR->new("$queryname $ttl $queryclass A $rdata");
	push (@logans, "$queryname $ttl $queryclass A $rdata");
	# IP-Adressen für NS und MX in Additional section
	my $ns1ip = getIP("ns1.$queryname");
	my $ns2ip = getIP("ns2.$queryname");
	push @add, Net::DNS::RR->new("ns1.$queryname $ttl $queryclass A $ns1ip");
	push @add, Net::DNS::RR->new("ns2.$queryname $ttl $queryclass A $ns2ip");
	push @logans, "ns1.$queryname $ttl $queryclass A $ns1ip";
	push @logans, "ns2.$queryname $ttl $queryclass A $ns2ip";
	my $mx1ip = getIP("mx1.$queryname");
	my $mx2ip = getIP("mx2.$queryname");
	push @add, Net::DNS::RR->new("mx1.$queryname $ttl $queryclass A $mx1ip");
	push @add, Net::DNS::RR->new("mx2.$queryname $ttl $queryclass A $mx2ip");
	push (@logans, "mx1.$queryname $ttl $queryclass A $mx1ip");
	push (@logans, "mx2.$queryname $ttl $queryclass A $mx2ip");
	$resultcode = "NOERROR";
    }

    elsif ($querytype eq "CNAME") {
	# irgendwelche Namen
	push @ans, Net::DNS::RR->new("$queryname $ttl $queryclass CNAME host.$queryname");
	push (@logans, "$queryname $ttl $queryclass CNAME host.$queryname");
	$resultcode = "NOERROR";
    }

    elsif ($querytype eq "AXFR") {
	$resultcode = "REFUSED";
    }

    elsif ($querytype eq "AAAA") {
	$resultcode = "NOERROR";
    }

    else {
#	$resultcode = "NXDOMAIN";
	$resultcode = "NOTIMP";
    }

    &INetSim::Log::SubLog("[$rhost] recv: Query Type ".$querytype.", Class ".$queryclass.", Name ".$queryname, $serviceName, $$);
    if ($resultcode ne "NXDOMAIN" && $resultcode ne "REFUSED" && $resultcode ne "NOTIMP" && $resultcode ne "SERVFAIL") {
	foreach my $msg (@logans){
	    &INetSim::Log::SubLog("[$rhost] send: ".$msg, $serviceName, $$);
	}
	$stat_success = 1;
    }
    else {
	&INetSim::Log::SubLog("[$rhost] send: ;Error: $resultcode.", $serviceName, $$);
    }
    &INetSim::Log::SubLog("[$rhost] disconnect", $serviceName, $$);
    &INetSim::Log::SubLog("[$rhost] stat: $stat_success qtype=$querytype qclass=$queryclass qname=$queryname", $serviceName, $$);
    return ($resultcode, \@ans, \@auth, \@add, {aa => 1});
}


sub getIP {
    my $hostname = lc(shift);

    my %static_host_to_ip = &INetSim::Config::getConfigHash("DNS_StaticHostToIP");

    if (defined $static_host_to_ip{$hostname}) {
	return $static_host_to_ip{$hostname};
    }
    else {
	return &INetSim::Config::getConfigParameter("DNS_Default_IP");
    }
}


sub getHost {
    my $ip = lc(shift);

    my %static_ip_to_host = &INetSim::Config::getConfigHash("DNS_StaticIPToHost");

    if (defined $static_ip_to_host{$ip}) {
	return $static_ip_to_host{$ip};
    }
    else {
	return &INetSim::Config::getConfigParameter("DNS_Default_Hostname") . "." . &INetSim::Config::getConfigParameter("DNS_Default_Domainname");
    }
}


1;
#############################################################
#
# History:
#
# Version 0.46  (2010-09-18) th
# - check for broken version 0.65 of Net::DNS
#
# Version 0.45  (2009-09-25) me
# - changed answer to server version queries and set query class to CH
#
# Version 0.44  (2009-09-24) me
# - added new config parameter 'DNS_Version'
#
# Version 0.43  (2008-08-27) me
# - added logging of process id
#
# Version 0.42  (2008-08-20) me
# - added handling of queries for hosts called 'wpad' (look at
#   http://tools.ietf.org/html/draft-cooper-webi-wpad-00 for details)
#
# Version 0.41  (2008-06-26) me
# - added checks for uninitialized variables
# - changed answer to unknown query types to 'NOTIMP' (not implemented)
# - added logging of result code if an error occurs
#
# Version 0.40  (2008-06-12) me
# - changed handling of AAAA queries (according to RFC 4074)
#
# Version 0.39  (2008-06-12) me
# - added handling of AAAA queries (returns NOTIMP)
#
# Version 0.38  (2007-12-31) th
# - change process name
#
# Version 0.37  (2007-05-15) th
# - switch user and group
#
# Version 0.36  (2007-04-27) th
# - use getConfigParameter, getConfigHash
#
# Version 0.35  (2007-04-24) th
# - replaced die() call if creating server fails
#
# Version 0.34  (2007-04-21) me
# - added logging of status for use with &INetSim::Report::GenReport()
#
# Version 0.33  (2007-04-05) th
# - made bind address configurable
#
# Version 0.32  (2007-04-02) th
# - added handling of SOA queries
# - moved additional information in responses from 'answer'
#   to 'additional' section
# - added resolving of configured static addresses and names
#
# Version 0.31  (2007-03-27) th
# - added configuration options
#   $INetSim::Config::DNS_ServiceName
#   $INetSim::Config::DNS_BindPort
#
# Version 0.3   (2007-03-17) th
# - added configuration options
#   $INetSim::Config::DNS_Default_IP
#   $INetSim::Config::DNS_Default_Hostname
#   $INetSim::Config::DNS_Default_Domainname
#
# Version 0.2b  (2007-03-15) me
#
#############################################################
