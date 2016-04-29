# -*- perl -*-
#
# INetSim::NTP - A fake NTP server
#
# RFC 1305, 2030 - (Simple) Network Time Protocol v1-4
#
# (c)2007-2013 Matthias Eckert, Thomas Hungenberg
#
# Version 0.49   (2009-08-28)
#
# For history/changelog see bottom of this file.
#
#############################################################

package INetSim::NTP;

use strict;
use warnings;
use Time::HiRes;
use base qw(INetSim::GenericServer);

use constant NTP_ADJ => 2208988800;



sub configure_hook {
    my $self = shift;

    $self->{server}->{host}   = &INetSim::Config::getConfigParameter("Default_BindAddress"); # bind to address
    $self->{server}->{port}   = &INetSim::Config::getConfigParameter("NTP_BindPort");  # bind to port
    $self->{server}->{proto}  = 'udp';                              # UDP protocol
    $self->{server}->{user}   = &INetSim::Config::getConfigParameter("Default_RunAsUser");       # user to run as
    $self->{server}->{group}  = &INetSim::Config::getConfigParameter("Default_RunAsGroup");    # group to run as
    $self->{server}->{setsid} = 0;                                  # do not daemonize
    $self->{server}->{no_client_stdout} = 1;                        # do not attach client to STDOUT
    $self->{server}->{log_level} = 0;                               # do not log anything
#    $self->{server}->{udp_recv_len} = 960;                          # default is 4096

    $self->{servicename} = &INetSim::Config::getConfigParameter("NTP_ServiceName");
    $self->{max_childs} = &INetSim::Config::getConfigParameter("Default_MaxChilds");

    $self->{server_ip} = &INetSim::Config::getConfigParameter("NTP_Server_IP");
    $self->{strict_checks} = &INetSim::Config::getConfigParameter("NTP_StrictChecks");
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
    my $diff_seconds = 0;

    ##### init for variables
    my $recvmsg = "";
    my $sendmsg = "";
    my $ReceiveTime = 0;
    my $cur_time = 0;
    my $valid = 1;

    ##### client
    my $C_Byte1 = 0;
    my $C_Leap_Indicator = 0;
    my $C_NTP_Version = 0;
    my $C_Mode = 0;
    my $C_Stratum = 0;
    my $C_Poll = 0;
    my $C_Precision = 0;
    my $C_Root_Delay_w1 = 0;
    my $C_Root_Delay_w2 = 0;
    my $C_Root_Delay = 0;
    my $C_Root_Dispersion_w1 = 0;
    my $C_Root_Dispersion_w2 = 0;
    my $C_Root_Dispersion = 0;
    my $C_Reference_Clock_Identifier = 0;
    my $C_Reference_Time_w1 = 0;
    my $C_Reference_Time_w2 = 0;
    my $C_Reference_Time = 0;
    my $C_Originate_Time_w1 = 0;
    my $C_Originate_Time_w2 = 0;
    my $C_Originate_Time = 0;
    my $C_Receive_Time_w1 = 0;
    my $C_Receive_Time_w2 = 0;
    my $C_Receive_Time = 0;
    my $C_Transmit_Time_w1 = 0;
    my $C_Transmit_Time_w2 = 0;
    my $C_Transmit_Time = 0;

    ##### server
    my $S_Byte1 = 0;
    my $S_Leap_Indicator = 0;
    my $S_NTP_Version = 4;
    my $S_Mode = 2;
    my $S_Stratum = 2;
    my $S_Poll = 6;
    my $S_Precision = -20;
    my $S_Root_Delay_w1 = 0;
    my $S_Root_Delay_w2 = 0;
    my $S_Root_Delay = 0;
    my $S_Root_Dispersion_w1 = 0;
    my $S_Root_Dispersion_w2 = 0;
    my $S_Root_Dispersion = 0;
    my $S_Reference_Clock_Identifier = unpack("N", pack("C4", split(/\./, $self->{server_ip})));
    my $S_Reference_Time_w1 = 0;
    my $S_Reference_Time_w2 = 0;
    my $S_Reference_Time = 0;
    my $S_Originate_Time_w1 = 0;
    my $S_Originate_Time_w2 = 0;
    my $S_Originate_Time = 0;
    my $S_Receive_Time_w1 = 0;
    my $S_Receive_Time_w2 = 0;
    my $S_Receive_Time = 0;
    my $S_Transmit_Time_w1 = 0;
    my $S_Transmit_Time_w2 = 0;
    my $S_Transmit_Time = 0;

    &INetSim::Log::SubLog("[$rhost:$rport] connect", $self->{servicename}, $$);
    if ($self->{server}->{numchilds} >= $self->{max_childs}) {
	print $client "Maximum number of connections ($self->{max_childs}) exceeded.\n";
	&INetSim::Log::SubLog("[$rhost:$rport] Connection refused - maximum number of connections ($self->{max_childs}) exceeded.", $self->{servicename}, $$);
    }
    else {
 	$recvmsg = $self->{server}->{udp_data};

        # check packet length - valid packets must be 48 or 68 bytes long
        if (length($recvmsg) != 48 && length($recvmsg) != 68) {
            &INetSim::Log::SubLog("[$rhost:$rport] recv: invalid ntp packet (packet length is not 48 or 68 bytes)", $self->{servicename}, $$);
            &INetSim::Log::SubLog("[$rhost:$rport] disconnect", $self->{servicename}, $$);
            return;
        }

        # if packet size equals to 68, drop the last 20 bytes
        if (length($recvmsg) == 68) {
            $recvmsg = substr($recvmsg, 0, 48);
        }

	# arrival time of the client packet
	$ReceiveTime = &INetSim::FakeTime::get_faketime();

	# split the packet
	(
	    $C_Byte1,
	    $C_Stratum,
	    $C_Poll,
	    $C_Precision,
	    $C_Root_Delay_w1,
	    $C_Root_Delay_w2,
	    $C_Root_Dispersion_w1,
	    $C_Root_Dispersion_w2,
	    $C_Reference_Clock_Identifier,
	    $C_Reference_Time_w1,
	    $C_Reference_Time_w2,
	    $C_Originate_Time_w1,
	    $C_Originate_Time_w2,
	    $C_Receive_Time_w1,
	    $C_Receive_Time_w2,
	    $C_Transmit_Time_w1,
	    $C_Transmit_Time_w2
	) = unpack ("C3 c  n B16 n B16  a4  N B32  N B32  N B32  N B32", $recvmsg);

        # if byte 1 is zero -> abort
	if (! $C_Byte1) {
            &INetSim::Log::SubLog("[$rhost:$rport] recv: invalid ntp packet (first byte is zero)", $self->{servicename}, $$);
            &INetSim::Log::SubLog("[$rhost:$rport] disconnect", $self->{servicename}, $$);
            return;
        }

        # originate timestamp AND receive timestamp must not be zero
        if ($self->{strict_checks} && ($C_Originate_Time_w1 || $C_Receive_Time_w1)) {
            &INetSim::Log::SubLog("[$rhost:$rport] recv: invalid ntp packet (originate and/or receive timestamps are not zero)", $self->{servicename}, $$);
            &INetSim::Log::SubLog("[$rhost:$rport] disconnect", $self->{servicename}, $$);
            return;
        }

	# split byte 1
	$C_Leap_Indicator = ($C_Byte1 & 192) >> 6;
	$C_NTP_Version = ($C_Byte1 & 56) >> 3;
	$C_Mode = $C_Byte1 & 7;

        # if leap indicator not 0 or 3 -> abort
        if ($self->{strict_checks} && ($C_Leap_Indicator != 0 && $C_Leap_Indicator != 3)) {
            &INetSim::Log::SubLog("[$rhost:$rport] recv: invalid ntp packet (wrong leap indicator value)", $self->{servicename}, $$);
            &INetSim::Log::SubLog("[$rhost:$rport] disconnect", $self->{servicename}, $$);
            return;
        }

        # according to the rfc, ntp version must be taken from client packet, therefore it should be between 1 and 4
	if ($C_NTP_Version >= 1 && $C_NTP_Version <= 4) {
	    $S_NTP_Version = $C_NTP_Version;
	}
        else {
            &INetSim::Log::SubLog("[$rhost:$rport] recv: invalid ntp packet (wrong ntp version)", $self->{servicename}, $$);
            &INetSim::Log::SubLog("[$rhost:$rport] disconnect", $self->{servicename}, $$);
	    return;
	}

        # mode must be 4 (server), if client mode was 3 (client), else 2 (symmetric passive)
	if ($C_Mode == 3) {
	    $S_Mode = 4;
	}
        elsif ($C_Mode == 1 || $C_Mode == 2) {
	    $S_Mode = 2;
	}
        else {
            # if mode is not between 1 and 3 -> abort
            &INetSim::Log::SubLog("[$rhost:$rport] recv: invalid ntp packet (wrong client mode)", $self->{servicename}, $$);
            &INetSim::Log::SubLog("[$rhost:$rport] disconnect", $self->{servicename}, $$);
            return;
        }

        # stratum should be 0 (unspecified)
        if ($self->{strict_checks} && ($C_Stratum != 0)) {
            &INetSim::Log::SubLog("[$rhost:$rport] recv: invalid ntp packet (wrong stratum)", $self->{servicename}, $$);
            &INetSim::Log::SubLog("[$rhost:$rport] disconnect", $self->{servicename}, $$);
            return;
        }

        # poll is taken from client and should be in range 1-14
	if ($C_Poll) {
	    # set to 1..17 as temp. workaround ==> ToDo
	    if ($C_Poll >= 1 && $C_Poll <= 17) {
	        $S_Poll = $C_Poll;
	    }
            else {
                # poll not in range and not 0 -> abort
                &INetSim::Log::SubLog("[$rhost:$rport] recv: invalid ntp packet (poll interval out of range)", $self->{servicename}, $$);
                &INetSim::Log::SubLog("[$rhost:$rport] disconnect", $self->{servicename}, $$);
	        return;
	    }
	}
        else {
            # else set poll to 6 (64s)
	    $S_Poll = 6;
	}
	$S_Root_Delay_w2 = &frac2bin($S_Root_Delay_w1);
	$S_Root_Dispersion_w2 = &frac2bin($S_Root_Dispersion_w1);
	$cur_time = &INetSim::FakeTime::get_faketime();

        # last sync time for server clock
	$S_Reference_Time_w1 = $cur_time + NTP_ADJ - 59;
        ##### fraction to ^^^
	$S_Reference_Time_w2 = &frac2bin($S_Reference_Time_w1);


#### RFC-konform ???  ToDo !!!!!!!
#
	  #if ($S_NTP_Version == 4 && $S_Stratum >= 2){
	  #  $S_Reference_Clock_Identifier = $S_Reference_Time_w2 >> 33;
	  #}
#
# Reference Identifier:
# ... In NTP Version 3 secondary servers, this is the 32-bit IPv4
# address of the reference source. In NTP Version 4 secondary servers,
# this is the low order 32 bits of the latest transmit timestamp of the
# reference source.... (rfc 2030, page 10)
#
#     ^^^^^^^^^^^
####


        # hmm, could be another check built in here !?
	if ($C_Transmit_Time_w1) {						# check transmit timestamp from client
	    $S_Originate_Time_w1 = $C_Transmit_Time_w1;				# last packet from other connection endpoint. Servers have to take the transmit timestamp from client
	    $S_Originate_Time_w2 = $C_Transmit_Time_w2;				# fraction to transmit timestamp
	}
        else {
	    $S_Originate_Time_w1 = 0;
	    $S_Originate_Time_w2 = &frac2bin($S_Originate_Time_w1);
	}
	$S_Receive_Time_w1 = $ReceiveTime + NTP_ADJ;				# arrival time of the last packet
	$S_Receive_Time_w2 = &frac2bin($S_Receive_Time_w1);			# fraction to ^^^
	$S_Transmit_Time_w1 = $cur_time + NTP_ADJ;				# packet sending time
	$S_Transmit_Time_w2 = &frac2bin($S_Transmit_Time_w1);			# fraction to ^^^
	# build byte 1
	$S_Leap_Indicator = ($S_Leap_Indicator << 6) ^ 63;			# bits 0+1,   => SHL 6, XOR with 00111111
	$S_NTP_Version = ($S_NTP_Version << 3) ^ 199;				# bits 2+3+4  => SHL 3, XOR with 11000111
	$S_Mode = $S_Mode ^ 248;						# bits 5+6+7  => XOR with 11111000
	$S_Byte1 = ($S_Leap_Indicator & $S_NTP_Version & $S_Mode);		# put it all together wit AND

	# build response packet
	$sendmsg = pack ("C3 c  n B16 n B16  N  N B32  N B32  N B32  N B32",
			  $S_Byte1,
			  $S_Stratum,
			  $S_Poll,
			  $S_Precision,
			  $S_Root_Delay_w1,
			  $S_Root_Delay_w2,
			  $S_Root_Dispersion_w1,
			  $S_Root_Dispersion_w2,
			  $S_Reference_Clock_Identifier,
			  $S_Reference_Time_w1,
			  $S_Reference_Time_w2,
			  $S_Originate_Time_w1,
			  $S_Originate_Time_w2,
			  $S_Receive_Time_w1,
			  $S_Receive_Time_w2,
			  $S_Transmit_Time_w1,
			  $S_Transmit_Time_w2
			  );

	# send out as fast as possible
	$client->send($sendmsg);
	$stat_success = 1;

	# analyse and log the client packet
	if ($C_Precision) {
	    $C_Precision = sprintf("%1.4e",2**$C_Precision);
	}
        else {
	    $C_Precision = 0;
	}
	if ($C_Root_Delay_w1 && $C_Root_Delay_w2) {
	    $C_Root_Delay_w1 += bin2frac($C_Root_Delay_w2);
	    $C_Root_Delay = sprintf("%.4f", $C_Root_Delay_w1);
	}
        else {
	    $C_Root_Delay = 0;
	}
	if ($C_Root_Dispersion_w1 && $C_Root_Dispersion_w2) {
	    $C_Root_Dispersion_w1 += bin2frac($C_Root_Dispersion_w2);
	    $C_Root_Dispersion = sprintf("%.4f", $C_Root_Dispersion_w1);
	}
        else {
	    $C_Root_Dispersion = 0;
	}
	if ($C_Stratum && $C_Reference_Clock_Identifier) {
	    if ($C_Stratum == 2 && $C_NTP_Version) {
	        if ($C_NTP_Version >= 1 && $C_NTP_Version <= 3) {
	            $C_Reference_Clock_Identifier = join(".", unpack("C4", pack("N", $C_Reference_Clock_Identifier)));
	        }
                elsif ($C_NTP_Version == 4) {
	            $C_Reference_Clock_Identifier = "low 32bits of latest TX timestamp of reference src";
	        }
	    }
	}
	if ($C_Reference_Clock_Identifier) {
            # replace non-printable characters with "."
            $C_Reference_Clock_Identifier =~ s/([^\x20-\x7e])/\./g;
	    if (! $C_Reference_Clock_Identifier || $C_Reference_Clock_Identifier =~ /^\x00/){$C_Reference_Clock_Identifier = "unspec"};
	}
        else{
	    $C_Reference_Clock_Identifier = "unspec"
	}
	if ($C_Reference_Time_w1 && $C_Reference_Time_w2) {
	    $C_Reference_Time_w1 += bin2frac($C_Reference_Time_w2);
	    $C_Reference_Time = sprintf("%10.5f", $C_Reference_Time_w1 - NTP_ADJ);
	}
        else {
	    $C_Reference_Time = sprintf("%10.5f", 0);
	}
	if ($C_Originate_Time_w1 && $C_Originate_Time_w2) {
	    $C_Originate_Time_w1 += bin2frac($C_Originate_Time_w2);
	    $C_Originate_Time = sprintf("%10.5f", $C_Originate_Time_w1 - NTP_ADJ);
	}
        else {
	    $C_Originate_Time = sprintf("%10.5f", 0);
	}
	if ($C_Receive_Time_w1 && $C_Receive_Time_w2) {
	    $C_Receive_Time_w1 += bin2frac($C_Receive_Time_w2);
	    $C_Receive_Time = sprintf("%10.5f", $C_Receive_Time_w1 - NTP_ADJ);
	}
        else {
	    $C_Receive_Time = sprintf("%10.5f", 0);
	}
	if ($C_Transmit_Time_w1 && $C_Transmit_Time_w2) {
	    $C_Transmit_Time_w1 += bin2frac($C_Transmit_Time_w2);
	    $C_Transmit_Time = sprintf("%10.5f", $C_Transmit_Time_w1 - NTP_ADJ);
	}
        else {
	    $C_Transmit_Time = sprintf("%10.5f", 0);
	}
	&INetSim::Log::SubLog("[$rhost:$rport] recv: VN = $C_NTP_Version,  Mode = $C_Mode,  LI = $C_Leap_Indicator", $self->{servicename}, $$);
	&INetSim::Log::SubLog("[$rhost:$rport] recv: Stratum = $C_Stratum,  Poll = $C_Poll,  Precision = $C_Precision", $self->{servicename}, $$);
	&INetSim::Log::SubLog("[$rhost:$rport] recv: Root Delay = $C_Root_Delay,  Root Dispersion = $C_Root_Dispersion", $self->{servicename}, $$);
	&INetSim::Log::SubLog("[$rhost:$rport] recv: Reference Identifier = $C_Reference_Clock_Identifier", $self->{servicename}, $$);
	&INetSim::Log::SubLog("[$rhost:$rport] recv: Reference Timestamp = $C_Reference_Time", $self->{servicename}, $$);
	&INetSim::Log::SubLog("[$rhost:$rport] recv: Originate Timestamp = $C_Originate_Time", $self->{servicename}, $$);
	&INetSim::Log::SubLog("[$rhost:$rport] recv: Receive Timestamp = $C_Receive_Time", $self->{servicename}, $$);
	&INetSim::Log::SubLog("[$rhost:$rport] recv: Transmit Timestamp = $C_Transmit_Time", $self->{servicename}, $$);

	# log the response packet
	$S_Leap_Indicator = $S_Leap_Indicator >> 6;
	$S_NTP_Version = ($S_NTP_Version & 56) >> 3;
	$S_Mode = $S_Mode & 7;
	$S_Precision = sprintf("%1.4e",2**$S_Precision);
	$S_Root_Delay_w1 += bin2frac($S_Root_Delay_w2);
	$S_Root_Delay = sprintf("%.4f", $S_Root_Delay_w1);
	$S_Root_Dispersion_w1 += bin2frac($S_Root_Dispersion_w2);
	$S_Root_Dispersion = sprintf("%.4f", $S_Root_Dispersion_w1);
	$S_Reference_Time_w1 += bin2frac($S_Reference_Time_w2);
	$S_Reference_Time = sprintf("%10.5f",$S_Reference_Time_w1 - NTP_ADJ);
	$S_Originate_Time_w1 += bin2frac($S_Originate_Time_w2);
	$S_Originate_Time = sprintf("%10.5f",$S_Originate_Time_w1 - NTP_ADJ);
	$S_Receive_Time_w1 += bin2frac($S_Receive_Time_w2);
	$S_Receive_Time = sprintf("%10.5f",$S_Receive_Time_w1 - NTP_ADJ);
	$S_Transmit_Time_w1 += bin2frac($S_Transmit_Time_w2);
	$S_Transmit_Time = sprintf("%10.5f",$S_Transmit_Time_w1 - NTP_ADJ);
	&INetSim::Log::SubLog("[$rhost:$rport] send: VN = $S_NTP_Version,  Mode = $S_Mode,  LI = $S_Leap_Indicator", $self->{servicename}, $$);
	&INetSim::Log::SubLog("[$rhost:$rport] send: Stratum = $S_Stratum,  Poll = $S_Poll,  Precision = $S_Precision", $self->{servicename}, $$);
	&INetSim::Log::SubLog("[$rhost:$rport] send: Root Delay = $S_Root_Delay,  Root Dispersion = $S_Root_Dispersion", $self->{servicename}, $$);
	&INetSim::Log::SubLog("[$rhost:$rport] send: Reference Identifier = $S_Reference_Clock_Identifier", $self->{servicename}, $$);
	&INetSim::Log::SubLog("[$rhost:$rport] send: Reference Timestamp = $S_Reference_Time   ".scalar(localtime($S_Reference_Time)), $self->{servicename}, $$);
	&INetSim::Log::SubLog("[$rhost:$rport] send: Originate Timestamp = $S_Originate_Time   ".scalar(localtime($S_Originate_Time)), $self->{servicename}, $$);
	&INetSim::Log::SubLog("[$rhost:$rport] send: Receive Timestamp = $S_Receive_Time   ".scalar(localtime($S_Receive_Time)), $self->{servicename}, $$);
	&INetSim::Log::SubLog("[$rhost:$rport] send: Transmit Timestamp = $S_Transmit_Time   ".scalar(localtime($S_Transmit_Time)), $self->{servicename}, $$);
    }
    &INetSim::Log::SubLog("[$rhost:$rport] disconnect", $self->{servicename}, $$);
    if ($stat_success == 1) {
	$S_Originate_Time = sprintf("%d", $S_Originate_Time);
	$S_Transmit_Time = sprintf("%d", $S_Transmit_Time);
        if ($S_Originate_Time > $S_Transmit_Time) {
	    $diff_seconds = $S_Originate_Time - $S_Transmit_Time;
	}
	elsif ($S_Originate_Time < $S_Transmit_Time) {
	    $diff_seconds = $S_Transmit_Time - $S_Originate_Time;
	}
        &INetSim::Log::SubLog("[$rhost:$rport] stat: $stat_success client=$S_Originate_Time server=$S_Transmit_Time secsdiff=$diff_seconds", $self->{servicename}, $$);
    }
    else {
        &INetSim::Log::SubLog("[$rhost:$rport] stat: $stat_success", $self->{servicename}, $$);
    }
}



sub bin2frac {
# convert a binary string to fraction
    my $input = shift;
    my @bin = split '', $input;
    my $frac = 0;
    while (@bin) {
        $frac = ($frac + pop @bin)/2;
    }
    $frac;
}



sub frac2bin{
# convert a fraction to binary string (B32)
    my $input = shift;
    my $frac = $input;
    my $bin ="";
    while (length($bin) < 32) {
        $bin = $bin . int($frac*2);
        $frac = $frac*2 - int($frac*2);
    }
    $bin;
}



1;
#############################################################
#
# History:
#
# Version 0.49  (2013-08-28) me
# - changed allowed poll range to 1..17 as temp. workaround
#
# Version 0.48  (2009-10-28) me
# - improved some code parts
#
# Version 0.47  (2009-09-01) me
# - changed comments
#
# Version 0.46  (2008-08-27) me
# - added logging of process id
#
# Version 0.45  (2008-03-15) me
# - added configuration option 'NTP_StrictChecks' to enable/disable
#   strict packet checks
# - changed check for non-printable characters in $C_Reference_Clock_Identifier
#   variable
#
# Version 0.44  (2008-03-15) me
# - removed check for given reference timestamp from client,
#   because some operating systems sets this to a non-zero value
# - changed logging messages for invalid packets
#
# Version 0.43  (2007-12-31) th
# - change process name
#
# Version 0.42  (2007-04-29) me
# - added some checks for valid packets
# - added logging of every invalid packet
#
# Version 0.41  (2007-04-26) th
# - use getConfigParameter
#
# Version 0.40  (2007-04-21) me
# - added logging of status for use with &INetSim::Report::GenReport()
#
# Version 0.39  (2007-04-20) me
# - fixed a ugly bug with byte 1
# - added check for byte 1
# - added flag for invalid packets
#
#
# Version 0.38  (2007-04-10) th
# - get fake time via &INetSim::FakeTime::get_faketime()
#   instead of accessing $INetSim::Config::FakeTimeDelta
#
# Version 0.37  (2007-04-05) me
# - changed check for MaxChilds, BindAddress, RunAsUser and
#   RunAsGroup
#
# Version 0.36b-c  (2007-03-30) me
# - forgotten debug output removed *argh*
# - fixed a typo
#
# Version 0.36  (2007-03-30) me
# - small bug fixes with variables
#
# Version 0.35  (2007-03-29) me
# - complete rewrite :-/
# - now checking some ranges from client packet
# - ToDo: the if-condition at lines 189-191
#
# Version 0.34  (2007-03-27) th
# - fixed logging if *_Time_H undefined
# - $S_Precision is negative, therefore cannot be pack'ed as
#   "C", so "C3" changed to "C2 c" when generating $send_msg
#
# Version 0.33  (2007-03-18) th
# - added configuration option $INetSim::Config::NTP_Server_IP
# - fixed double declaration of $S_Mode
#
# Version 0.32  (2007-03-16) th
# - added configuration option $INetSim::Config::FakeTimeDelta
#
# Version 0.31  (2007-03-15) th
# - small bug fixes with variables
#
# Version 0.3   (2007-03-14) me
#
#############################################################
