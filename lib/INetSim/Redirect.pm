# -*- perl -*-
#
# INetSim::Redirect - A modul to redirect network connections
#
# RFC 1700, 791, 793, 768, 792... - IP, TCP, UDP and ICMP...
#
# (c)2008-2010 Matthias Eckert, Thomas Hungenberg
#
# Version 0.20   (2010-04-10)
#
# For history/changelog see bottom of this file.
#
#############################################################

package INetSim::Redirect;

use strict;
use warnings;

use IPTables::IPv4::IPQueue qw(:constants);


my $serviceName = "redirect";
my $iptables_cmd;
my $externalAddress;
my $changeTTL;
my $redirectUnknown;
my @usedPorts;
my $dummyPortTCP;
my $dummyPortUDP;
my $ip_forward;
my $nf_conntrack;
my $icmp_ts = 0;

my %FORWARD;
my %REDIRECT;
my %FULLNAT;

my %IP;
my %TCP;
my %UDP;
my %ICMP;

my $MAC;
my $PROTO;
my $SRC_IP;
my $DST_IP;
my $TTL;
my $SRC_PORT;
my $DST_PORT;
my $TYPE;
my $CODE;
my $IN_DEV;
my $OUT_DEV;

my $PID = $$;
my $ipq;

my %type = (	0				=> "echo-reply",
		3				=> "destination-unreachable",
		4				=> "source-quench",
		5				=> "redirect",
		8				=> "echo-request",
		9				=> "router-advertisement",
		10				=> "router-solicitation",
		11				=> "time-exceeded",
		12				=> "parameter-problem",
		13				=> "timestamp-request",
		14				=> "timestamp-reply",
		17				=> "address-mask-request",
		18				=> "address-mask-reply",
		"echo-reply"			=> 0,
		"destination-unreachable"	=> 3,
		"source-quench"			=> 4,
		"redirect"			=> 5,
		"echo-request"			=> 8,
		"router-advertisement"		=> 9,
		"router-solicitation"		=> 10,
		"time-exceeded"			=> 11,
		"parameter-problem"		=> 12,
		"timestamp-request"		=> 13,
		"timestamp-reply"		=> 14,
		"address-mask-request"		=> 17,
		"address-mask-reply"		=> 18
);




sub check_requirements {
    my $my_ip = &INetSim::Config::getConfigParameter("Default_BindAddress");
    my @path = split (/:/, $ENV{PATH});
    my $iptables;
    my $modprobe;

    if ( $> != 0 ) {
        &INetSim::Log::MainLog("failed! Error: Sorry, you must be root to run this module!", $serviceName);
        exit 1;
    }
    if ($my_ip eq '0.0.0.0') {
        &INetSim::Log::MainLog("failed! Error: Sorry, this module doesn't work together with address '0.0.0.0'!", $serviceName);
        exit 1;
    }
    foreach (@path) {
        # search iptables in path
        if (! $iptables && -x "$_/iptables") {
            $iptables = "$_/iptables";
        }
        # search modprobe in path
        if (! $modprobe && -x "$_/modprobe") {
            $modprobe = "$_/modprobe";
        }
    }
    # return 0 - iptables not found or executable
    if (! $iptables) {
        &INetSim::Log::MainLog("failed! Error: Unable to run iptables command!", $serviceName);
        exit 1;
    }
    $iptables_cmd = $iptables;
    # final check
    `$iptables_cmd -nL &>/dev/null`;
    if (! $?) {
        if ($modprobe) {
            foreach my $km (qw/x_tables ip_tables/) {
                `$modprobe $km &>/dev/null`;
            }
        }
        return 1;
    }
    &INetSim::Log::MainLog("failed! Error: Unable to run iptables command!", $serviceName);
    exit 1;
}



sub parse_static_rules {
    $redirectUnknown = &INetSim::Config::getConfigParameter("Redirect_UnknownServices");
    $externalAddress = &INetSim::Config::getConfigParameter("Redirect_ExternalAddress");
    $changeTTL = &INetSim::Config::getConfigParameter("Redirect_ChangeTTL");
    $dummyPortTCP = &INetSim::Config::getConfigParameter("Dummy_TCP_BindPort");
    $dummyPortUDP = &INetSim::Config::getConfigParameter("Dummy_UDP_BindPort");
    my %rules = &INetSim::Config::getConfigHash("Redirect_StaticRules");
    @usedPorts = &INetSim::Config::getUsedPorts();
    $icmp_ts = &INetSim::Config::getConfigParameter("Redirect_ICMP_Timestamp");
    my ($proto, $dst, $realdst);
    my ($dst_ip, $dst_port, $dst_type, $real_ip, $real_port);
    my ($key, $value);
    my $src_ip = "";
    my $dummy;

    foreach (keys %rules) {
        ($proto, $dst, $dst_ip, $dst_port, $realdst, $real_ip, $real_port, $key, $value) = undef;
        ($proto, $dst) = split(/,/, $_, 2);
        if (! defined ($proto) || ! $proto || $proto !~ /^(tc|ud|icm)p$/) {
            next;
        }
        $proto = lc($proto);
        # tcp/udp
        if ($proto =~ /(tc|ud)p/) {
            ($dst_ip, $dst_port) = split (/:/, $dst, 2);
            $realdst = $rules{$_};
            ($real_ip, $real_port) = split (/:/, $realdst, 2);
            if ((! defined ($dst_ip) || ! $dst_ip) && (! defined ($dst_port) || ! $dst_port)) {
                next;
            }
            if ((! defined ($real_ip) || ! $real_ip) && (! defined ($real_port) || ! $real_port)) {
                next;
            }
            $key = "$proto:$dst_ip:$dst_port";
            $value = "$real_ip:$real_port";
            if ((! defined ($real_ip) || ! $real_ip) && defined ($real_port) && $real_port) {
                # redirect to local port
                #   10.1.1.6:88     =>      :80
                #          *:6667   =>      :7
                if (! defined ($REDIRECT{$key})) {
                    $REDIRECT{$key} = $value;
                    next;
                }
            }
            elsif (defined ($dst_ip) && $dst_ip && defined ($real_ip) && $real_ip && defined ($dst_port) && $dst_port && defined ($real_port) && $real_port && $dst_ip eq $real_ip && $dst_port eq $real_port) {
                # don't change anything - pass trough
                # 204.152.191.37:80 =>      204.152.191.37:80
                if (! defined ($FORWARD{$key})) {
                    $FORWARD{$key} = $value;
                    next;
                }
            }
            elsif (defined ($real_ip) && $real_ip && ((defined ($dst_port) && $dst_port) || (defined ($dst_ip) && $dst_ip))) {
                # redirect to external host
                # 193.99.144.80:80  =>      72.14.221.104:80
                #             *:99  =>      81.169.154.213:25
                #      10.1.1.1:*   =>      192.168.1.1:*
                if (! defined ($FULLNAT{$key})) {
                    $FULLNAT{$key} = $value;
                    next;
                }
            }
        }
        # icmp
        else {
            ($dst_ip, $dst_type) = split (/:/, $dst, 2);
            $realdst = $rules{$_};
            ($real_ip, $dummy) = split (/:/, $realdst, 2);
            if (! $dst_ip && ! $dst_type) {
                next;
            }
            if (! $real_ip) {
                next;
            }
            if (defined $dst_type && $dst_type) {
                $key = "$proto:$dst_ip:$type{$dst_type}";
            }
            else {
                $key = "$proto:$dst_ip:";
            }
            $value = "$real_ip";
            if ($dst_ip && $real_ip && $dst_ip eq $real_ip) {
                # don't change anything - pass trough
                # 10.1.1.6:echo-request  =>  10.1.1.6
                # 10.1.1.6:              =>  10.1.1.6
                if (! defined ($FORWARD{$key})) {
                    $FORWARD{$key} = $value;
                    next;
                }
            }
            elsif (($dst_ip || $dst_type) && $real_ip) {
                # redirect to external host
                # 10.1.1.6:echo-request  =>  204.152.191.37
                # 10.1.1.6:              =>  204.152.191.37
                # :echo-request          =>  204.152.191.37
                if (! defined ($FULLNAT{$key})) {
                    $FULLNAT{$key} = $value;
                    next;
                }
            }
        }
    }
}



sub ipt {
    my $cmd_opts = shift;

    if (defined ($cmd_opts) && $cmd_opts) {
        $cmd_opts =~ /([\x20-\x7e]+)/;
        $cmd_opts = $1;
        my $res = `$iptables_cmd $cmd_opts` || '-';
        ($?) or return 1;
        &INetSim::Log::DebugLog("Error: 'iptables $cmd_opts' $res", $serviceName, $$);
    }
    return 0;
}



sub ip_forward {
    my $cmd = shift || "status";
    my $value;

    if (open (PROC, "/proc/sys/net/ipv4/ip_forward")) {
        chomp($value = <PROC>);
        close PROC;
    }
    $cmd =~ /(status|enable|disable)/;
    $cmd = $1;
    $value =~ /(0|1)/;
    $value = $1;
    if (defined ($cmd)) {
        if ((! $value && $cmd eq "enable") && open (PROC, "> /proc/sys/net/ipv4/ip_forward")) {
            print PROC "1\n";
            close PROC;
            &INetSim::Log::SubLog("IP forward enabled.", $serviceName, $$);
            return 2;
        }
        elsif (($value && $cmd eq "disable") && open (PROC, "> /proc/sys/net/ipv4/ip_forward")) {
            print PROC "0\n";
            close PROC;
            &INetSim::Log::SubLog("IP forward disabled.", $serviceName, $$);
            return 1;
        }
        elsif ($cmd eq "status") {
            return $value;
        }
    }
    return 0;
}



sub nf_conntrack {
    my $cmd = shift || "status";
    my $value;

    # kernel version < 2.6.29  =>  return
    (-f "/proc/sys/net/netfilter/nf_conntrack_acct") or return;
    # kernel version >= 2.6.29  =>  toggle nf_conntrack
    if (open (CTL, "/proc/sys/net/netfilter/nf_conntrack_acct")) {
        chomp($value = <CTL>);
        close CTL;
    }
    $cmd =~ /(status|enable|disable)/;
    $cmd = $1;
    $value =~ /(0|1)/;
    $value = $1;
    ($cmd) or return;
    if ((! $value && $cmd eq "enable") && open (CTL, ">", "/proc/sys/net/netfilter/nf_conntrack_acct")) {
        print CTL "1\n";
        close CTL;
        &INetSim::Log::SubLog("Connection tracking enabled.", $serviceName, $$);
        return 2;
    }
    elsif (($value && $cmd eq "disable") && open (CTL, ">", "/proc/sys/net/netfilter/nf_conntrack_acct")) {
        print CTL "0\n";
        close CTL;
        &INetSim::Log::SubLog("Connection tracking disabled.", $serviceName, $$);
        return 1;
    }
    elsif ($cmd eq "status") {
        return $value;
    }
    return 0;
}



sub create_chains {
    # save original value for ip_forward
    $ip_forward = &ip_forward("status");
    # save original value for nf_conntrack
    $nf_conntrack = &nf_conntrack("status");
    # enable nf_conntrack
    &nf_conntrack("enable");
    # create chain in mangle table for userspace queueing of packets
    &ipt("-t mangle -N INetSim_$PID");
    # create chain for redirecting packets to local ports
    &ipt("-t nat -N INetSim_REDIRECT_$PID");
    # create chain for changing the destination ip/port of packets
    &ipt("-t nat -N INetSim_DNAT_$PID");
    # create chain for complete forward
    &ipt("-t mangle -N INetSim_FORWARD_$PID");
    # create chain for changing the source ip/port of packets
    &ipt("-t nat -N INetSim_SNAT_$PID");
    # add rule to redirect all packets with state NEW to userspace
    &ipt("-t mangle -A INetSim_$PID -m state --state NEW -j QUEUE");
    # add rule to redirect all icmp timestamp replies to userspace
    &ipt("-t mangle -A INetSim_$PID -p icmp --icmp-type 14 -j QUEUE");
    # now redirect all packets to inetsim chains
    # queue
    &ipt("-t mangle -A PREROUTING -j INetSim_$PID");
    # redirect
    &ipt("-t nat -A PREROUTING -j INetSim_REDIRECT_$PID");
    # dnat
    &ipt("-t nat -A PREROUTING -j INetSim_DNAT_$PID");
    # forward
    &ipt("-t mangle -A FORWARD -j INetSim_FORWARD_$PID");
    # snat
    &ipt("-t nat -A POSTROUTING -j INetSim_SNAT_$PID");
    # ttl change
    &ipt("-t mangle -I PREROUTING -j CONNMARK --restore-mark");
    if ($changeTTL) {
        foreach (34..64) {
            &ipt("-t mangle -A POSTROUTING -m connmark --mark $_ -j TTL --ttl-set $_");
        }
    }
}



sub delete_chains {
    # set original value for ip_forward
    if (defined $ip_forward && $ip_forward == 0) {
        &ip_forward("disable");
    }
    # queue
    &ipt("-t mangle -D PREROUTING -j INetSim_$PID");
    # redirect
    &ipt("-t nat -D PREROUTING -j INetSim_REDIRECT_$PID");
    # dnat
    &ipt("-t nat -D PREROUTING -j INetSim_DNAT_$PID");
    # forward
    &ipt("-t mangle -D FORWARD -j INetSim_FORWARD_$PID");
    # snat
    &ipt("-t nat -D POSTROUTING -j INetSim_SNAT_$PID");
    # ttl change
    &ipt("-t mangle -D PREROUTING -j CONNMARK --restore-mark");
    if ($changeTTL) {
        foreach (34..64) {
            &ipt("-t mangle -D POSTROUTING -m connmark --mark $_ -j TTL --ttl-set $_");
        }
    }
    # delete SNAT chain
    &ipt("-t nat -F INetSim_SNAT_$PID");
    &ipt("-t nat -X INetSim_SNAT_$PID");
    # delete FORWARD chain    
    &ipt("-t mangle -F INetSim_FORWARD_$PID");
    &ipt("-t mangle -X INetSim_FORWARD_$PID");
    # delete DNAT chain
    &ipt("-t nat -F INetSim_DNAT_$PID");
    &ipt("-t nat -X INetSim_DNAT_$PID");
    # delete REDIRECT chain
    &ipt("-t nat -F INetSim_REDIRECT_$PID");
    &ipt("-t nat -X INetSim_REDIRECT_$PID");
    # delete chains in mangle table
    &ipt("-t mangle -D INetSim_$PID -p icmp --icmp-type 14 -j QUEUE");
    &ipt("-t mangle -D INetSim_$PID -m state --state NEW -j QUEUE");
    &ipt("-t mangle -F INetSim_$PID");
    &ipt("-t mangle -X INetSim_$PID");
    # set original value for nf_conntrack
    if (defined $nf_conntrack && $nf_conntrack == 0) {
        &nf_conntrack("disable");
    }
}



sub process_packet_icmp {
    my $full = "icmp:" . $DST_IP . ":" . $TYPE;
    my $type = "icmp::" . $TYPE;
    my $host = "icmp:" . $DST_IP . ":";
    my $my_ip = &INetSim::Config::getConfigParameter("Default_BindAddress");
    my $ignore_bootp = &INetSim::Config::getConfigParameter("Redirect_IgnoreBootp");
    my $ignore_netbios = &INetSim::Config::getConfigParameter("Redirect_IgnoreNetbios");
    my $real_ip;
    my $ttl_dec;
    my $ttl_set;
    my $used;
    my $dummy;
    my %pp = ( 8 => 0, 13 => 14, 17 => 18 );

    if ((defined ($FULLNAT{$full}) && $FULLNAT{$full}) || (defined ($FULLNAT{$type}) && $FULLNAT{$type}) || (defined ($FULLNAT{$host}) && $FULLNAT{$host})) {
        if (defined ($FULLNAT{$full}) && $FULLNAT{$full}) {
            ($real_ip, $dummy) = split(/:/, $FULLNAT{$full}, 2);
            # 172.16.1.2:echo-request => 10.1.1.1
        }
        elsif (defined ($FULLNAT{$type}) && $FULLNAT{$type}) {
            ($real_ip, $dummy) = split(/:/, $FULLNAT{$type}, 2);
            # :echo-request => 10.1.1.1
        }
        elsif (defined ($FULLNAT{$host}) && $FULLNAT{$host}) {
            ($real_ip, $dummy) = split(/:/, $FULLNAT{$host}, 2);
            # 172.16.1.2: => 10.1.1.1
        }
        if (defined ($real_ip) && $real_ip) {
            if (! defined ($externalAddress) || ! $externalAddress) {
                &INetSim::Log::SubLog("[$SRC_IP:$type{$TYPE}] ERROR: Network Address Translation from '$DST_IP:$type{$TYPE}' to '$real_ip:$type{$TYPE}' is impossible because external address is unset!", $serviceName, $$);
                return 0;
            }
            # enable ip forward if disabled
            if (! &ip_forward) {
                if (! &ip_forward("enable")) {
                    &INetSim::Log::SubLog("[$SRC_IP:$type{$TYPE}] ERROR: Network Address Translation from '$DST_IP:$type{$TYPE}' to '$real_ip:$type{$TYPE}' is impossible because cannot enable ip_forward!", $serviceName, $$);
                    return 0;
                }
            }
            # dnat rule
            &ipt("-t nat -A INetSim_DNAT_$PID -s $SRC_IP -d $DST_IP -p $PROTO --icmp-type $TYPE -j DNAT --to-destination $real_ip");
            # snat rule
            &ipt("-t nat -A INetSim_SNAT_$PID -s $SRC_IP -d $real_ip -p $PROTO --icmp-type $TYPE -j SNAT --to-source $externalAddress");
            # mark rule for more packets with the same properties
            if ($TYPE == 14 && $icmp_ts) {
                # mark timestamp reply packets with 2
                &ipt("-t mangle -I INetSim_$PID -s $SRC_IP -d $DST_IP -p $PROTO --icmp-type $TYPE -j MARK --set-mark 2");
                if (defined $pp{$TYPE}) {
                    &ipt("-t mangle -I INetSim_$PID -s $real_ip -d $externalAddress -p $PROTO --icmp-type $pp{$TYPE} -j MARK --set-mark 2");
                }
                else {
                    &ipt("-t mangle -I INetSim_$PID -s $real_ip -d $externalAddress -p $PROTO -j MARK --set-mark 2");
                }
            }
            else {
                &ipt("-t mangle -I INetSim_$PID -s $SRC_IP -d $DST_IP -p $PROTO --icmp-type $TYPE -j MARK --set-mark 1");
                if (defined $pp{$TYPE}) {
                    &ipt("-t mangle -I INetSim_$PID -s $real_ip -d $externalAddress -p $PROTO --icmp-type $pp{$TYPE} -j MARK --set-mark 1");
                }
                else {
                    &ipt("-t mangle -I INetSim_$PID -s $real_ip -d $externalAddress -p $PROTO -j MARK --set-mark 1");
                }
            }
            # change ttl
            if ($changeTTL) {
                $ttl_set = int(rand(30) + 34);
                &ipt("-t mangle -I INetSim_$PID -s $SRC_IP -d $DST_IP -p $PROTO --icmp-type $TYPE -m connmark --mark 0 -j CONNMARK --set-mark $ttl_set");
                &INetSim::Log::SubLog("[$SRC_IP:$type{$TYPE}] Translating $PROTO connections from host '$SRC_IP' ($MAC), source changed from '$SRC_IP' to '$externalAddress', destination changed from '$DST_IP:$type{$TYPE}' to '$real_ip:$type{$TYPE}', TTL set to $ttl_set.", $serviceName, $$);
            }
            else {
                &INetSim::Log::SubLog("[$SRC_IP:$type{$TYPE}] Translating $PROTO connections from host '$SRC_IP' ($MAC), source changed from '$SRC_IP' to '$externalAddress', destination changed from '$DST_IP:$type{$TYPE}' to '$real_ip:$type{$TYPE}'.", $serviceName, $$);
            }
            return 1;
        }
    }
    elsif (defined ($FORWARD{$full}) && $FORWARD{$full}) {
        # enable ip forward if disabled
        if (! &ip_forward) {
            if (! &ip_forward("enable")) {
                &INetSim::Log::SubLog("[$SRC_IP:$type{$TYPE}] ERROR: Forward to '$DST_IP:$type{$TYPE}' is impossible because cannot enable ip_forward!", $serviceName, $$);
                return 0;
            }
        }
        # forward rules
        &ipt("-t mangle -A INetSim_FORWARD_$PID -s $SRC_IP -d $DST_IP -p $PROTO --icmp-type $TYPE -j FORWARD");
        &ipt("-t mangle -A INetSim_FORWARD_$PID -d $SRC_IP -s $DST_IP -p $PROTO -j FORWARD");
        # mark rules for more packets with the same properties
        if ($TYPE == 14 && $icmp_ts) {
            # mark timestamp reply packets with 2
            &ipt("-t mangle -I INetSim_$PID -s $SRC_IP -d $DST_IP -p $PROTO --icmp-type $TYPE -j MARK --set-mark 2");
            if (defined $pp{$TYPE}) {
                &ipt("-t mangle -I INetSim_$PID -d $SRC_IP -s $DST_IP -p $PROTO --icmp-type $pp{$TYPE} -j MARK --set-mark 2");
            }
            else {
                &ipt("-t mangle -I INetSim_$PID -d $SRC_IP -s $DST_IP -p $PROTO -j MARK --set-mark 2");
            }
        }
        else {
            &ipt("-t mangle -I INetSim_$PID -s $SRC_IP -d $DST_IP -p $PROTO --icmp-type $TYPE -j MARK --set-mark 1");
            if (defined $pp{$TYPE}) {
                &ipt("-t mangle -I INetSim_$PID -d $SRC_IP -s $DST_IP -p $PROTO --icmp-type $pp{$TYPE} -j MARK --set-mark 1");
            }
            else {
                &ipt("-t mangle -I INetSim_$PID -d $SRC_IP -s $DST_IP -p $PROTO -j MARK --set-mark 1");
            }
        }
        # change ttl
        if ($changeTTL) {
            $ttl_set = int(rand(30) + 34);
            &ipt("-t mangle -I INetSim_$PID -s $SRC_IP -d $DST_IP -p $PROTO --icmp-type $TYPE -m connmark --mark 0 -j CONNMARK --set-mark $ttl_set");
            &INetSim::Log::SubLog("[$SRC_IP:$type{$TYPE}] Forwarding $PROTO connections from host '$SRC_IP' ($MAC) to destination '$DST_IP:$type{$TYPE}', TTL set to $ttl_set.", $serviceName, $$);
        }
        else {
            &INetSim::Log::SubLog("[$SRC_IP:$type{$TYPE}] Forwarding $PROTO connections from host '$SRC_IP' ($MAC) to destination '$DST_IP:$type{$TYPE}'.", $serviceName, $$);
        }
        return 1;
    }
    else {
        # mark rule for more packets with the same properties
        if ($TYPE == 14 && $icmp_ts) {
            # mark timestamp reply packets with 2
            &ipt("-t mangle -I INetSim_$PID -s $SRC_IP -d $DST_IP -p $PROTO --icmp-type $TYPE -j MARK --set-mark 2");
        }
        else {
            &ipt("-t mangle -I INetSim_$PID -s $SRC_IP -d $DST_IP -p $PROTO --icmp-type $TYPE -j MARK --set-mark 1");
        }
        &INetSim::Log::SubLog("[$SRC_IP:$type{$TYPE}] No rule for $PROTO connections from host '$SRC_IP' ($MAC) to destination '$DST_IP:$type{$TYPE}' - ignored.", $serviceName, $$);
    }
    return 0;
}



sub process_packet_tcpudp {
    my $full = "$PROTO:$DST_IP:$DST_PORT";
    my $port = "$PROTO" . "::" . "$DST_PORT";
    my $host = "$PROTO:$DST_IP:";
    my $my_ip = &INetSim::Config::getConfigParameter("Default_BindAddress");
    my $ignore_bootp = &INetSim::Config::getConfigParameter("Redirect_IgnoreBootp");
    my $ignore_netbios = &INetSim::Config::getConfigParameter("Redirect_IgnoreNetbios");
    my ($real_ip, $real_port);
    my $ttl_dec;
    my $ttl_set;
    my $used;

    # if configured, ignore dhcp packets
    if ($ignore_bootp && $PROTO eq "udp" && ("$SRC_IP:$SRC_PORT" eq "0.0.0.0:68" && "$DST_IP:$DST_PORT" eq "255.255.255.255:67" || "$DST_IP:$DST_PORT" eq "0.0.0.0:68" && "$SRC_IP:$SRC_PORT" eq "255.255.255.255:67")) {
        return 0;
    }

    # if configured, ignore netbios packets
    if ($ignore_netbios && $PROTO eq "udp" && $SRC_PORT == $DST_PORT && ($SRC_PORT == 137 || $SRC_PORT == 138) && ($DST_IP =~ /\.255$/ || $SRC_IP =~ /\.255$/)) {
        return 0;
    }

    if ((defined ($FULLNAT{$full}) && $FULLNAT{$full}) || (defined ($FULLNAT{$port}) && $FULLNAT{$port}) || (defined ($FULLNAT{$host}) && $FULLNAT{$host})) {
        ($real_ip, $real_port) = undef;
        if (defined ($FULLNAT{$full}) && $FULLNAT{$full}) {
            ($real_ip, $real_port) = split(/:/, $FULLNAT{$full}, 2);
        }
        elsif (defined ($FULLNAT{$port}) && $FULLNAT{$port}) {
            ($real_ip, $real_port) = split(/:/, $FULLNAT{$port}, 2);
        }
        elsif (defined ($FULLNAT{$host}) && $FULLNAT{$host}) {
            ($real_ip, $real_port) = split(/:/, $FULLNAT{$host}, 2);
        }
        if (! defined ($real_port) || ! $real_port) {
            $real_port = $DST_PORT;
        }
        if (defined ($real_ip) && $real_ip) {
            if (! defined ($externalAddress) || ! $externalAddress) {
                &INetSim::Log::SubLog("[$SRC_IP:$SRC_PORT] ERROR: Network Address Translation from '$DST_IP:$DST_PORT' to '$real_ip:$real_port' is impossible because external address is unset!", $serviceName, $$);
                return 0;
            }
            # enable ip forward if disabled
            if (! &ip_forward) {
                if (! &ip_forward("enable")) {
                    &INetSim::Log::SubLog("[$SRC_IP:$SRC_PORT] ERROR: Network Address Translation from '$DST_IP:$DST_PORT' to '$real_ip:$real_port' is impossible because cannot enable ip_forward!", $serviceName, $$);
                    return 0;
                }
            }
            # dnat rule
            &ipt("-t nat -A INetSim_DNAT_$PID -s $SRC_IP -d $DST_IP -p $PROTO --dport $DST_PORT -j DNAT --to-destination $real_ip:$real_port");
            # snat rule
            &ipt("-t nat -A INetSim_SNAT_$PID -s $SRC_IP -d $real_ip -p $PROTO --dport $real_port -j SNAT --to-source $externalAddress");
            # mark rule for more packets with the same properties
            &ipt("-t mangle -I INetSim_$PID -s $SRC_IP -d $DST_IP -p $PROTO --dport $DST_PORT -j MARK --set-mark 1");
            &ipt("-t mangle -I INetSim_$PID -s $real_ip -d $externalAddress -p $PROTO --sport $real_port -j MARK --set-mark 1");
            # change ttl
            if ($changeTTL) {
                $ttl_set = int(rand(30) + 34);
                &ipt("-t mangle -I INetSim_$PID -s $SRC_IP -d $DST_IP -p $PROTO --dport $DST_PORT -m connmark --mark 0 -j CONNMARK --set-mark $ttl_set");
                &INetSim::Log::SubLog("[$SRC_IP:$SRC_PORT] Translating $PROTO connections from host '$SRC_IP' ($MAC), source changed from '$SRC_IP' to '$externalAddress', destination changed from '$DST_IP:$DST_PORT' to '$real_ip:$real_port', TTL set to $ttl_set.", $serviceName, $$);
            }
            else {
                &INetSim::Log::SubLog("[$SRC_IP:$SRC_PORT] Translating $PROTO connections from host '$SRC_IP' ($MAC), source changed from '$SRC_IP' to '$externalAddress', destination changed from '$DST_IP:$DST_PORT' to '$real_ip:$real_port'.", $serviceName, $$);
            }
            return 1;
        }
    }
    elsif (defined ($FORWARD{$full}) && $FORWARD{$full}) {
        # enable ip forward if disabled
        if (! &ip_forward) {
            if (! &ip_forward("enable")) {
                &INetSim::Log::SubLog("[$SRC_IP:$SRC_PORT] ERROR: Forward to '$DST_IP:$DST_PORT' is impossible because cannot enable ip_forward!", $serviceName, $$);
                return 0;
            }
        }
        # forward rules
        &ipt("-t mangle -A INetSim_FORWARD_$PID -s $SRC_IP -d $DST_IP -p $PROTO --dport $DST_PORT -j FORWARD");
        &ipt("-t mangle -A INetSim_FORWARD_$PID -d $SRC_IP -s $DST_IP -p $PROTO --sport $DST_PORT -j FORWARD");
        # mark rules for more packets with the same properties
        &ipt("-t mangle -I INetSim_$PID -s $SRC_IP -d $DST_IP -p $PROTO --dport $DST_PORT -j MARK --set-mark 1");
        &ipt("-t mangle -I INetSim_$PID -d $SRC_IP -s $DST_IP -p $PROTO --sport $DST_PORT -j MARK --set-mark 1");
        # change ttl
        if ($changeTTL) {
            $ttl_set = int(rand(30) + 34);
            &ipt("-t mangle -I INetSim_$PID -s $SRC_IP -d $DST_IP -p $PROTO --dport $DST_PORT -m connmark --mark 0 -j CONNMARK --set-mark $ttl_set");
            &INetSim::Log::SubLog("[$SRC_IP:$SRC_PORT] Forwarding $PROTO connections from host '$SRC_IP' ($MAC) to destination '$DST_IP:$DST_PORT', TTL set to $ttl_set.", $serviceName, $$);
        }
        else {
            &INetSim::Log::SubLog("[$SRC_IP:$SRC_PORT] Forwarding $PROTO connections from host '$SRC_IP' ($MAC) to destination '$DST_IP:$DST_PORT'.", $serviceName, $$);
        }
        return 1;
    }
    elsif ((defined ($REDIRECT{$full}) && $REDIRECT{$full}) || (defined ($REDIRECT{$port}) && $REDIRECT{$port})) {
        ($real_ip, $real_port) = undef;
        if (defined ($REDIRECT{$full}) && $REDIRECT{$full}) {
            ($real_ip, $real_port) = split(/:/, $REDIRECT{$full}, 2);
        }
        elsif (defined ($REDIRECT{$port}) && $REDIRECT{$port}) {
            ($real_ip, $real_port) = split(/:/, $REDIRECT{$port}, 2);
        }
        if (defined ($real_port) && $real_port && (! defined ($real_ip) || ! $real_ip)) {
            # redirect rule
            &ipt("-t nat -A INetSim_REDIRECT_$PID -s $SRC_IP -d $DST_IP -p $PROTO --dport $DST_PORT -j REDIRECT --to $real_port");
            # mark rule for more packets with the same properties
            &ipt("-t mangle -I INetSim_$PID -s $SRC_IP -d $DST_IP -p $PROTO --dport $DST_PORT -j MARK --set-mark 1");
            # change ttl
            if ($changeTTL) {
                $ttl_set = int(rand(30) + 34);
                &ipt("-t mangle -I INetSim_$PID -s $SRC_IP -d $DST_IP -p $PROTO --dport $DST_PORT -m connmark --mark 0 -j CONNMARK --set-mark $ttl_set");
                &INetSim::Log::SubLog("[$SRC_IP:$SRC_PORT] Redirecting $PROTO connections from host '$SRC_IP' ($MAC), destination changed from '$DST_IP:$DST_PORT' to '$my_ip:$real_port', TTL set to $ttl_set.", $serviceName, $$);
            }
            else {
                &INetSim::Log::SubLog("[$SRC_IP:$SRC_PORT] Redirecting $PROTO connections from host '$SRC_IP' ($MAC), destination changed from '$DST_IP:$DST_PORT' to '$my_ip:$real_port'.", $serviceName, $$);
            }
            return 1;
        }
    }
    elsif ($redirectUnknown) {
            foreach $used (@usedPorts) {
                if ($used eq "$PROTO:$DST_PORT") {
                    if ($DST_IP eq $my_ip) {
                        # mark rule for more packets with the same properties
                        &ipt("-t mangle -I INetSim_$PID -s $SRC_IP -d $DST_IP -p $PROTO --dport $DST_PORT -j MARK --set-mark 1");
                        # change ttl
                        if ($changeTTL) {
                            $ttl_set = int(rand(30) + 34);
                            &ipt("-t mangle -I INetSim_$PID -s $SRC_IP -d $DST_IP -p $PROTO --dport $DST_PORT -m connmark --mark 0 -j CONNMARK --set-mark $ttl_set");
                            &INetSim::Log::SubLog("[$SRC_IP:$SRC_PORT] No redirect needed for $PROTO connections from host '$SRC_IP' ($MAC) to destination '$DST_IP:$DST_PORT', TTL set to $ttl_set.", $serviceName, $$);
                        }
                        else {
                            &INetSim::Log::SubLog("[$SRC_IP:$SRC_PORT] No redirect needed for $PROTO connections from host '$SRC_IP' ($MAC) to destination '$DST_IP:$DST_PORT'.", $serviceName, $$);
                        }
                        return 0;
                    }
                    else {
                        # redirect rule
                        &ipt("-t nat -A INetSim_REDIRECT_$PID -s $SRC_IP -d $DST_IP -p $PROTO --dport $DST_PORT -j REDIRECT --to $DST_PORT");
                        # mark rule for more packets with the same properties
                        &ipt("-t mangle -I INetSim_$PID -s $SRC_IP -d $DST_IP -p $PROTO --dport $DST_PORT -j MARK --set-mark 1");
                        # change ttl
                        if ($changeTTL) {
                            $ttl_set = int(rand(30) + 34);
                            &ipt("-t mangle -I INetSim_$PID -s $SRC_IP -d $DST_IP -p $PROTO --dport $DST_PORT -m connmark --mark 0 -j CONNMARK --set-mark $ttl_set");
                            &INetSim::Log::SubLog("[$SRC_IP:$SRC_PORT] Redirecting $PROTO connections from host '$SRC_IP' ($MAC), destination changed from '$DST_IP:$DST_PORT' to '$my_ip:$DST_PORT', TTL set to $ttl_set.", $serviceName, $$);
                        }
                        else {
                            &INetSim::Log::SubLog("[$SRC_IP:$SRC_PORT] Redirecting $PROTO connections from host '$SRC_IP' ($MAC), destination changed from '$DST_IP:$DST_PORT' to '$my_ip:$DST_PORT'.", $serviceName, $$);
                        }
                        return 1;
                    }
                }
            }
            if ($PROTO eq "tcp" && defined ($dummyPortTCP) && $dummyPortTCP) {
                # redirect rule
                &ipt("-t nat -A INetSim_REDIRECT_$PID -s $SRC_IP -d $DST_IP -p $PROTO --dport $DST_PORT -j REDIRECT --to $dummyPortTCP");
                # mark rule for more packets with the same properties
                &ipt("-t mangle -I INetSim_$PID -s $SRC_IP -d $DST_IP -p $PROTO --dport $DST_PORT -j MARK --set-mark 1");
                # change ttl
                if ($changeTTL) {
                    $ttl_set = int(rand(30) + 34);
                    &ipt("-t mangle -I INetSim_$PID -s $SRC_IP -d $DST_IP -p $PROTO --dport $DST_PORT -m connmark --mark 0 -j CONNMARK --set-mark $ttl_set");
                    &INetSim::Log::SubLog("[$SRC_IP:$SRC_PORT] Redirecting $PROTO connections from host '$SRC_IP' ($MAC), destination changed from '$DST_IP:$DST_PORT' to '$my_ip:$dummyPortTCP', TTL set to $ttl_set.", $serviceName, $$);
                }
                else {
                    &INetSim::Log::SubLog("[$SRC_IP:$SRC_PORT] Redirecting $PROTO connections from host '$SRC_IP' ($MAC), destination changed from '$DST_IP:$DST_PORT' to '$my_ip:$dummyPortTCP'.", $serviceName, $$);
                }
                return 1;
            }
            elsif ($PROTO eq "udp" && defined ($dummyPortUDP) && $dummyPortUDP) {
                # redirect rule
                &ipt("-t nat -A INetSim_REDIRECT_$PID -s $SRC_IP -d $DST_IP -p $PROTO --dport $DST_PORT -j REDIRECT --to $dummyPortUDP");
                # mark rule for more packets with the same properties
                &ipt("-t mangle -I INetSim_$PID -s $SRC_IP -d $DST_IP -p $PROTO --dport $DST_PORT -j MARK --set-mark 1");
                # change ttl
                if ($changeTTL) {
                    $ttl_set = int(rand(30) + 34);
                    &ipt("-t mangle -I INetSim_$PID -s $SRC_IP -d $DST_IP -p $PROTO --dport $DST_PORT -m connmark --mark 0 -j CONNMARK --set-mark $ttl_set");
                    &INetSim::Log::SubLog("[$SRC_IP:$SRC_PORT] Redirecting $PROTO connections from host '$SRC_IP' ($MAC), destination changed from '$DST_IP:$DST_PORT' to '$my_ip:$dummyPortUDP', TTL set to $ttl_set.", $serviceName, $$);
                }
                else {
                    &INetSim::Log::SubLog("[$SRC_IP:$SRC_PORT] Redirecting $PROTO connections from host '$SRC_IP' ($MAC), destination changed from '$DST_IP:$DST_PORT' to '$my_ip:$dummyPortUDP'.", $serviceName, $$);
                }
                return 1;
            }
    }
    else {
        # mark rule for more packets with the same properties
        &ipt("-t mangle -I INetSim_$PID -s $SRC_IP -d $DST_IP -p $PROTO --dport $DST_PORT -j MARK --set-mark 1");
        &INetSim::Log::SubLog("[$SRC_IP:$SRC_PORT] No rule for $PROTO connections from host '$SRC_IP' ($MAC) to destination '$DST_IP:$DST_PORT' - ignored.", $serviceName, $$);
    }
    return 0;
}



sub close_queue {
    $ipq->close();
}



sub process_queue {
    while () {
        my $msg = $ipq->get_message();
        if (!defined $msg) {
            next if IPTables::IPv4::IPQueue->errstr eq 'Timeout';
        }
        my $mac = $msg->hw_addr();
        my $ip_packet = $msg->payload();
        $IN_DEV = $msg->indev_name();
        $OUT_DEV = $msg->outdev_name();
        my $mark = $msg->mark();
        my $new_packet;
        my $changed = 0;

        if (! $mark) {
            &split_mac($mac);
            &split_ip($ip_packet);
            if ($PROTO eq "tcp") {
                &split_tcp($IP{data});
                &process_packet_tcpudp;
            }
            elsif ($PROTO eq "udp") {
                &split_udp($IP{data});
                &process_packet_tcpudp;
            }
            elsif ($PROTO eq "icmp") {
                &split_icmp($IP{data});
                &process_packet_icmp;
                # handle icmp timestamp replies, if configured
                if ($icmp_ts && $TYPE == 14) {
                    my $ts_reply = &fake_ts_reply;
                    if ($ts_reply) {
                        $ICMP{receive} = $ts_reply;
                        $ICMP{transmit} = $ts_reply;
                        $IP{data} = &build_icmp;
                        $new_packet = &build_ip;
                        $changed = 1;
                    }
                }
            }
        }
        elsif ($icmp_ts && $mark == 2) {
            &split_mac($mac);
            &split_ip($ip_packet);
            if ($PROTO eq "icmp") {
                &split_icmp($IP{data});
                if ($TYPE == 14) {
                    my $ts_reply = &fake_ts_reply;
                    if ($ts_reply) {
                        $ICMP{receive} = $ts_reply;
                        $ICMP{transmit} = $ts_reply;
                        $IP{data} = &build_icmp;
                        $new_packet = &build_ip;
                        $changed = 1;
                    }
                }
            }
        }

        if (! $changed) {
            $ipq->set_verdict($msg->packet_id, NF_ACCEPT) or die IPTables::IPv4::IPQueue->errstr;
        }
        else {
            $ipq->set_verdict($msg->packet_id, NF_ACCEPT, length ($new_packet), $new_packet) or die IPTables::IPv4::IPQueue->errstr;
        }
    }
    $ipq->close();
}



sub fake_ts_reply {
    ($icmp_ts) or return;
    if ($icmp_ts == 1) {
        # ms
        return int((&INetSim::FakeTime::get_faketime() % 86400) * 1000);
    }
    elsif ($icmp_ts == 2) {
        # sec
        return int(&INetSim::FakeTime::get_faketime() | 2147483648);
    }
    return;
}



sub split_mac {
    $MAC = unpack('H12', shift);
    $MAC =~ s/(..)/$1:/g;
    $MAC =~ s/:$//;
}



sub split_ip {
    my $raw = shift;
    my ($IPVersion, $HeaderLength, $Flags, $FragOffset, $SrcIP, $DstIP, $Options, $Data);
    my $OptionLength;
    my $OptionBytes;

    # unpack
    my ($Byte1, $TOS, $Length, $ID, $Word1, $ttl, $Protocol, $Checksum, $Source, $Destination, $Options_Data) = unpack ("C C n n n C C n N N a*", $raw);
    # get ip version
    $IPVersion = ($Byte1 & 240) >> 4;
    # get header length
    $HeaderLength = $Byte1 & 15;
    # get flags
    $Flags = $Word1 >> 13;
    # get fragmentation offset
    $FragOffset = ($Word1 & 8191) << 3;
    # get source and destination ip (dotted quad)
    $SrcIP = sprintf("%d.%d.%d.%d", (($Source & 0xFF000000) >> 24), (($Source & 0x00FF0000) >> 16), (($Source & 0x0000FF00) >> 8), ($Source & 0x000000FF));
    $DstIP = sprintf("%d.%d.%d.%d", (($Destination & 0xFF000000) >> 24), (($Destination & 0x00FF0000) >> 16), (($Destination & 0x0000FF00) >> 8), ($Destination & 0x000000FF));
    # get the length of options (header length minus 5*4 bytes)
    $OptionLength = $HeaderLength - 5;
    if ($OptionLength < 0) {
        $OptionLength = 0;
    }
    # length of options is option length * 4 byte (RFC 791, page 11)
    $OptionBytes = $OptionLength * 4;
    # split options and data
    ($Options, $Data) = unpack ("a$OptionBytes a*", $Options_Data);
    %IP = ();
    %IP = (     "ip_version"    =>      $IPVersion,
                "hdr_length"    =>      $HeaderLength,
                "tos"           =>      $TOS,
                "length"        =>      $Length,
                "id"            =>      $ID,
                "flags"         =>      $Flags,
                "frag_offset"   =>      $FragOffset,
                "ttl"           =>      $ttl,
                "protocol"      =>      $Protocol,
                "checksum"      =>      $Checksum,
                "src_ip"        =>      $SrcIP,
                "dst_ip"        =>      $DstIP,
                "options"       =>      $Options,
                "data"          =>      $Data
    );
    if ($Protocol == 6) {
        $PROTO = "tcp";
    }
    elsif ($Protocol == 17) {
        $PROTO = "udp";
    }
    elsif ($Protocol == 1) {
        $PROTO = "icmp";
    }
    else {
        $PROTO = "";
    }
    $SRC_IP = $SrcIP;
    $DST_IP = $DstIP;
    $TTL = $ttl;
}


sub build_ip {
    my $Checksum;
    my $IPVersion;
    my $HeaderLength;
    my $Byte1;
    my $Word4;
    my $Word;
    my $Flags;
    my $Number;
    my $Header;
    my ($Source, $Destination);

    # set checksum to zero for recalculation
    $Checksum = 0;
    # ip version and ip header length
    $IPVersion = $IP{ip_version} << 4;
    $Byte1 = $IPVersion | $IP{hdr_length};
    # flags and fragmentation offset
    $Flags = $IP{flags} << 13;
    $Word4 = $Flags | $IP{frag_offset};
    # src and dst ip
    $Source = gethostbyname($IP{src_ip});
    $Destination = gethostbyname($IP{dst_ip});
    # build the header for checksumming
    $Header = pack ("C C n n n C C n a4 a4 a*", $Byte1, $IP{tos}, $IP{length}, $IP{id}, $Word4, $IP{ttl}, $IP{protocol}, $Checksum, $Source, $Destination, $IP{options});
    # get the number of words
    $Number = int (length ($Header) / 2);
    # now compute the checksum
    foreach $Word ( unpack ("S$Number", $Header) ) {
        $Checksum += $Word;
    }
    $Checksum = ($Checksum >> 16) + ($Checksum & 65535);
    $Checksum = unpack ("n", pack ("S", ~(($Checksum >> 16) + $Checksum) & 65535));
    $IP{checksum} = $Checksum;
    # pack
    return ( pack ("C C n n n C C n a4 a4 a* a*", $Byte1, $IP{tos}, $IP{length}, $IP{id}, $Word4, $IP{ttl}, $IP{protocol}, $Checksum, $Source, $Destination, $IP{options}, $IP{data}) );
}



sub split_icmp {
    my $raw = shift;
    my $Payload;
    my ($Identifier, $SeqNumber);
    my ($Pointer, $Unused, $Orig_IPHeader, $Orig_Data64);
    my ($OriginateTime, $ReceiveTime, $TransmitTime);
    my $Gateway;
    my $GatewayIP;

    my ($Type, $Code, $Checksum, $Data) = unpack ("C C n a*", $raw);

    %ICMP = ();
    # echo-request or echo-reply
    if ($Type == 8 || $Type == 0) {
        ($Identifier, $SeqNumber, $Payload) = unpack ("n n a*", $Data);
        %ICMP = ( "identifier"  =>      $Identifier,
                  "seqnumber"   =>      $SeqNumber,
                  "payload"     =>      $Payload
        );
    }
    # parameter problem
    elsif ($Type == 12) {
        ($Pointer, $Unused, $Orig_IPHeader, $Orig_Data64) = unpack ("C C3 a20 a8", $Data);
        %ICMP = ( "pointer"     =>      $Pointer,
                  "unused"      =>      $Unused,
                  "ipheader"    =>      $Orig_IPHeader,
                  "data64"      =>      $Orig_Data64
        );
    }
    # timestamp-request or timestamp-reply
    elsif ($Type == 13 || $Type == 14) {
        ($Identifier, $SeqNumber, $OriginateTime, $ReceiveTime, $TransmitTime) = unpack ("n n N N N", $Data);
        %ICMP = ( "identifier"  =>      $Identifier,
                  "seqnumber"   =>      $SeqNumber,
                  "originate"   =>      $OriginateTime,
                  "receive"     =>      $ReceiveTime,
                  "transmit"    =>      $TransmitTime
        );
    }
    # information-request or information-reply
    elsif ($Type == 15 || $Type == 16) {
        ($Identifier, $SeqNumber) = unpack ("n n", $Data);
        %ICMP = ( "identifier"  =>      $Identifier,
                  "seqnumber"   =>      $SeqNumber
        );
    }
    # destination-unreachable or source-quench or time-exceeded
    elsif ($Type == 3 || $Type == 4 || $Type == 11) {
        ($Unused, $Orig_IPHeader, $Orig_Data64) = unpack ("C4 a20 a8", $Data);
        %ICMP = ( "unused"      =>      $Unused,
                  "ipheader"    =>      $Orig_IPHeader,
                  "data64"      =>      $Orig_Data64
        );
    }
    # redirect
    elsif ($Type == 5) {
        ($Gateway, $Orig_IPHeader, $Orig_Data64) = unpack ("N a20 a8", $Data);
        $GatewayIP = sprintf ("%d.%d.%d.%d", (($GatewayIP & 0xFF000000) >> 24), (($GatewayIP & 0x00FF0000) >> 16), (($GatewayIP & 0x0000FF00) >> 8), ($GatewayIP & 0x000000FF));
        %ICMP = ( "gateway"     =>      $Gateway,
                  "ipheader"    =>      $Orig_IPHeader,
                  "data64"      =>      $Orig_Data64,
                  "gatewayip"   =>      $GatewayIP
        );
    }
    $TYPE = $ICMP{type} = $Type;
    $CODE = $ICMP{code} = $Code;
    $ICMP{checksum} = $Checksum;
    $ICMP{rawdata} = $Data;
}



sub build_icmp {
    my $Packet;
    my ($Number, $Checksum, $Word);

    # set checksum to zero for recalculation
    $Checksum = 0;
    # echo-request or echo-reply
    if ($ICMP{type} == 8 || $ICMP{type} == 0) {
        $Packet = pack ("C C n n n a*", $ICMP{type}, $ICMP{code}, $Checksum, $ICMP{identifier}, $ICMP{seqnumber}, $ICMP{payload});
    }
    # parameter problem
    elsif ($ICMP{type} == 12) {
        $Packet = pack ("C C n C C3 a20 a8", $ICMP{type}, $ICMP{code}, $Checksum, $ICMP{pointer}, $ICMP{unused}, $ICMP{ipheader}, $ICMP{data64});
    }
    # timestamp-request or timestamp-reply
    elsif ($ICMP{type} == 13 || $ICMP{type} == 14) {
        $Packet = pack ("C C n n n N N N", $ICMP{type}, $ICMP{code}, $Checksum, $ICMP{identifier}, $ICMP{seqnumber}, $ICMP{originate}, $ICMP{receive}, $ICMP{transmit});
    }
    # information-request or information-reply
    elsif ($ICMP{type} == 15 || $ICMP{type} == 16) {
        $Packet = pack ("C C n n n", $ICMP{type}, $ICMP{code}, $Checksum, $ICMP{identifier}, $ICMP{seqnumber});
    }
    # destination-unreachable or source-quench or time-exceeded
    elsif ($ICMP{type} == 3 || $ICMP{type} == 4 || $ICMP{type} == 11) {
        $Packet = pack ("C C n C4 a20 a8", $ICMP{type}, $ICMP{code}, $Checksum, $ICMP{unused}, $ICMP{ipheader}, $ICMP{data64});
    }
    # redirect
    elsif ($ICMP{type} == 5) {
        $Packet = pack ("C C n N a20 a8", $ICMP{type}, $ICMP{code}, $Checksum, $ICMP{gateway}, $ICMP{ipheader}, $ICMP{data64});
    }
    # unknown type, leave it unchanged
    else {
        $Packet = pack ("C C n a*", $ICMP{type}, $ICMP{code}, $Checksum, $ICMP{rawdata});
    }
    # get the number of words
    $Number = int (length ($Packet) / 2);
    # now compute the checksum
    foreach $Word ( unpack ("S$Number", $Packet) ) {
        $Checksum += $Word;
    }
    $Checksum = ($Checksum >> 16) + ($Checksum & 65535);
    $Checksum = pack ("S", ~(($Checksum >> 16) + $Checksum) & 65535);
    return ( substr($Packet, 0, 2) . $Checksum . substr($Packet, 4) );
}



sub split_udp {
    my $raw = shift;

    # unpack
    my ($SrcPort, $DstPort, $Length, $Checksum, $Data) = unpack ("n n n n a*", $raw);    
    %UDP = ();
    %UDP = (    "src_port"      =>      $SrcPort,
                "dst_port"      =>      $DstPort,
                "length"        =>      $Length,
                "checksum"      =>      $Checksum,
                "data"          =>      $Data
    );
    $SRC_PORT = $SrcPort;
    $DST_PORT = $DstPort;
}



sub build_udp {
    my $Packet;
    my $PseudoHeader;
    my $UDPHeader;
    my $PseudoPacket;
    my ($Source, $Destination, $Protocol);     # some ip parts are required for pseudo header (RFC 768, page 2)
    my ($SrcPort, $DstPort, $Length, $Checksum, $Data);
    my $Number;
    my $Word;

    # set checksum to zero for recalculation
    $Checksum = 0;
    # get the packet length
    $Length = length( $UDP{data} ) + 8;
    # src and dst ip
    $Source = gethostbyname($IP{src_ip});
    $Destination = gethostbyname($IP{dst_ip});
    # build the pseudo header
    $PseudoHeader = pack ("a4 a4 C C n", $Source, $Destination, 0, 17, $Length);
    # build the udp header
    $UDPHeader = pack ("n n n n", $UDP{src_port}, $UDP{dst_port}, $UDP{length}, $Checksum);
    # pack data
    $Data = pack ("a*", $UDP{data});
    # padding data if length mod 2 = 1
    if (length($Data) % 2) {
        $Data .= pack ("a", 0);
    }
    # putting it all together for checksumming
    $PseudoPacket = $PseudoHeader . $UDPHeader . $Data;
    # get the number of words
    $Number = int (length ($PseudoPacket) / 2);
    # now compute the checksum
    foreach $Word ( unpack ("S$Number", $PseudoPacket) ) {
        $Checksum += $Word;
    }
    $Checksum = ($Checksum >> 16) + ($Checksum & 65535);
    $Checksum = unpack ("n", pack ("S", ~(($Checksum >> 16) + $Checksum) & 65535));
    $UDP{checksum} = $Checksum;
    # pack
    return ( pack ("n n n n a*", $UDP{src_port}, $UDP{dst_port}, $Length, $UDP{checksum}, $UDP{data}) );
}



sub split_tcp {
    my $raw = shift;
    my ($Reserved, $DataOffset, $ControlBits, $Options, $Data);
    my $OptionLength;
    my $OptionBytes;

    my ($SrcPort, $DstPort, $SeqNumber, $AckNumber, $Word1, $Window, $Checksum, $UrgPointer, $Options_Data) = unpack ("n n N N n n n n a*", $raw);
    # get the data offset
    $DataOffset = ($Word1 & 61440) >> 12;
    # get reserved field
    $Reserved = ($Word1 & 4032) >> 6;
    # get the control bits (aka flags)
    $ControlBits = $Word1 & 63;
    # get the length of options (data offset minus 5*4 bytes)
    $OptionLength = $DataOffset - 5;
    if ($OptionLength < 0) {
        $OptionLength = 0;
    }
    # length of options is option length * 4 byte (RFC 793, page 16)
    $OptionBytes = $OptionLength * 4;
    # split options and data
    ($Options, $Data) = unpack ("a$OptionBytes a*", $Options_Data);
    %TCP = ();
    %TCP = (    "src_port"      =>      $SrcPort,
                "dst_port"      =>      $DstPort,
                "seq_number"    =>      $SeqNumber,
                "ack_number"    =>      $AckNumber,
                "data_offset"   =>      $DataOffset,
                "reserved"      =>      $Reserved,
                "flags"         =>      $ControlBits,
                "window"        =>      $Window,
                "checksum"      =>      $Checksum,
                "urg_pointer"   =>      $UrgPointer,
                "options"       =>      $Options,
                "data"          =>      $Data
    );
    $SRC_PORT = $SrcPort;
    $DST_PORT = $DstPort;
}



sub build_tcp {
    my $Packet;
    my $PseudoHeader;
    my $TCPHeader;
    my $PseudoPacket;
    my ($Source, $Destination, $Protocol);     # some ip parts are required for pseudo header (RFC 793, page 16)
    my ($SrcPort, $DstPort, $Length, $Checksum, $Data);
    my $DataOffset;
    my $Reserved;
    my $Number;
    my $Word;
    my $Word4;

    # set checksum to zero for recalculation
    $Checksum = 0;
    # get the packet length
    $Length = 20 + length( $TCP{options} ) + length( $TCP{data} );
    # src and dst ip
    $Source = gethostbyname($IP{src_ip});
    $Destination = gethostbyname($IP{dst_ip});
    # build the pseudo header
    $PseudoHeader = pack ("a4 a4 C C n", $Source, $Destination, 0, 6, $Length);    
    # build the tcp header
    $DataOffset = $TCP{data_offset} << 12;
    $Reserved = $TCP{reserved} << 6;
    $Word4 = $DataOffset | $Reserved | $TCP{flags};
    # pack
    $TCPHeader = pack ("n n N N n n n n a*", $TCP{src_port}, $TCP{dst_port}, $TCP{seq_number}, $TCP{ack_number}, $Word4, $TCP{window}, $Checksum, $TCP{urg_pointer}, $TCP{options});
    # pack data
    $Data = pack ("a*", $TCP{data});
    # padding data if length mod 2 = 1
    if (length($Data) % 2) {
        $Data .= pack ("a", 0);
    }
    # putting it all together for checksumming
    $PseudoPacket = $PseudoHeader . $TCPHeader . $Data;
    # get the number of words
    $Number = int (length ($PseudoPacket) / 2);
    # now compute the checksum
    foreach $Word ( unpack ("S$Number", $PseudoPacket) ) {
        $Checksum += $Word;
    }
    $Checksum = ($Checksum >> 16) + ($Checksum & 65535);
    $Checksum = unpack ("n", pack ("S", ~(($Checksum >> 16) + $Checksum) & 65535));
    $TCP{checksum} = $Checksum;
    # pack
    return ( pack ("n n N N n n n n a* a*", $TCP{src_port}, $TCP{dst_port}, $TCP{seq_number}, $TCP{ack_number}, $Word4, $TCP{window}, $Checksum, $TCP{urg_pointer}, $TCP{options}, $TCP{data}) );
}



sub run {
    $0 = "inetsim [$serviceName]";
    $SIG{'INT'} = $SIG{'HUP'} = $SIG{'PIPE'} = $SIG{'QUIT'} = $SIG{'TERM'} = 'IGNORE';
    $ENV{PATH} = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
    # check for uid=0 and iptables
    &check_requirements;
    # check - is ipqueue runnable ?
    eval {
           $ipq = new IPTables::IPv4::IPQueue(copy_mode => IPQ_COPY_PACKET, copy_range => 1500) or die IPTables::IPv4::IPQueue->errstr;
    };
    # isn't => exit
    if ($@) {
        &INetSim::Log::MainLog("failed! Error: $@", $serviceName);
        exit 1;
    }
    &parse_static_rules;
    &INetSim::Log::MainLog("started (PID $$)", $serviceName);
    $SIG{'TERM'} = sub { &delete_chains; &close_queue; &INetSim::Log::MainLog("stopped (PID $$)", $serviceName); exit 0;};
    &create_chains;
    &process_queue;
}



1;
#############################################################
#
# History:
#
# Version 0.20  (2010-04-10) me
# - bugfix: change all timestamp replies, not just the first packet
# - some small changes in functions check_requirements() and ipt()
#
# Version 0.19  (2010-04-02) me
# - changed code for icmp-timestamp replies (should be done yet)
#
# Version 0.18  (2010-03-31) me
# - added workaround for nf_conntrack in kernels >= 2.6.29, because
#   the nf_conntrack functionality is disabled by default for these.
#   Therefore added function nf_conntrack()
# - fix: do not die on IPQueue timeouts
# - added basic support to modify the timestamps in icmp-timestamp
#   packets (needs more work)
#
# Version 0.17  (2010-02-19) me
# - added function split_mac()
# - added logging of mac address
# - changed signal handlers a bit
# - added basic icmp support
#
# Version 0.16  (2008-08-27) me
# - added code to ignore bootp and netbios packets
# - added use of new configuration variables Redirect_IgnoreBootp
#   and Redirect_IgnoreNetbios
#
# Version 0.15  (2008-08-27) me
# - added logging of process id
# - added check for Default_BindAddress in function check_requirements()
#
# Version 0.14  (2008-06-24) me
# - code cleanup
#
# Version 0.13  (2008-06-19) me
# - small bugfix in function 'process_packet_tcpudp'
#
# Version 0.12  (2008-06-14) me
# - changed 'localhost' to 'Default_BindAddress' in function
#   process_packet_tcpudp()
#
# Version 0.11  (2008-06-13) me
# - changed redirect code for use with configuration variable
#   'Default_BindAddress'
# - fixed the code for random ttl values !!  :-D
# - changed some rules in functions create_chains() and
#   delete_chains()
# - renamed function process_packet() to process_packet_tcpudp()
#
# Version 0.10  (2008-06-12) me
# - changed code for redirects to used ports
#
# Version 0.9   (2008-03-19) me
# - removed logging of source port in function process_packet()
#
# Version 0.8   (2008-03-18) me
# - added functions split_icmp() and build_icmp()  ;-)
# - changed error messages in function check_requirements()
# - added simple check for ipqueue kernel support
# - added check for uid=0 in check_requirements()
#
# Version 0.7   (2008-03-17) me
# - disabled code for changing ttl values :-/
# - fixed a typo in function process_packet()
# - code cleanup
#
# Version 0.6   (2008-03-16) me
# - changed ttl code, set 'ttl-dec' to 'ttl-set'
# - added function ipt()
# - added function ip_forward()
# - added function process_packet()
# - removed functions add_redirect() and add_dnat()
# - changed rule for queue-target, so only new connections are
#   handled
# - removed code for different interfaces
# - moved configuration options to Config.pm and inetsim.conf
#
# Version 0.5   (2008-03-15) me
# - added check for 'IPTables::IPv4::IPQueue' (moved to INetSim.pm)
# - added function check_requirements()
# - added/removed support for changing uid and gid and for sudo,
#   because ipqueue doesn't work without root privileges *argh*
# - changed code for random ttl values (again and again...)
# - added function parse_static_rules()
#
# Version 0.4   (2008-03-12) me
# - added code to randomize ttl values, but this won't work
#   for redirected packets :-/  (possible TTL target bug ?)
#
# Version 0.3   (2008-03-09) me
# - complete rewrite, now using iptables for redirect
# - added functions create_chains() and delete_chains()
# - added function add_redirect() for redirects to local ports
# - added function add_dnat() for redirects to remote hosts/ports
# - changed function process_queue() to work with add_redirect()
#   and add_dnat()
# - added pid to all chain names
# - added fwmark value != 0 for new rules
# - changed create_chains() and process_queue() to process packets
#   with fwmark=0 only
# - ToDo: * change process uid and gid
#         * add sudo for iptables command
#         * add a rule parser
#         * move configuration options and rules to inetsim.conf
#         * add function for randomizing of ttl values ? :-)
#
# Version 0.2   (2008-03-08) me
# - fixed a bug with frag_offset in function split_ip() - added
#   left shift with 3
# - removed code for splitting IP and TCP options
# - added function build_udp() for udp reassembly
# - added function build_tcp() for tcp reassembly
# - added function build_ip() for ip reassembly
#
# Version 0.1   (2008-03-07) me
# - initial version
#
#############################################################
