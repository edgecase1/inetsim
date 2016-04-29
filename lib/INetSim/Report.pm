# -*- perl -*-
#
# INetSim::Report - INetSim reporting
#
# (c)2007-2013 Matthias Eckert, Thomas Hungenberg
#
# Version 0.50  (2013-08-14)
#
# For history/changelog see bottom of this file.
#
#############################################################

package INetSim::Report;

use strict;
use warnings;


sub GenReport {
    my $RE_DTime_PID = qr/^\[(\d+)\-(\d+)\-(\d+)\s(\d+:\d+:\d+)\]\s+\[(.*?)\]\s.*$/;
    my $RE_POP3 = qr/^\[(\d+)\-(\d+)\-(\d+)\s(\d+:\d+:\d+)\]\s+\[.*?\]\s\[(pop3_\d+_tcp)\s(\d+)\]\s\[(\d+\.\d+\.\d+\.\d+:\d+)\]\sstat:\s(\d)\sretrieved\=(\d+)\sdeleted\=(\d+)\sauth\=(.*?)\screds\=(.*)/;
    my $RE_POP3S = qr/^\[(\d+)\-(\d+)\-(\d+)\s(\d+:\d+:\d+)\]\s+\[.*?\]\s\[(pop3s_\d+_tcp)\s(\d+)\]\s\[(\d+\.\d+\.\d+\.\d+:\d+)\]\sstat:\s(\d)\sretrieved\=(\d+)\sdeleted\=(\d+)\sauth\=(.*?)\screds\=(.*)/;
    my $RE_SMTP = qr/^\[(\d+)\-(\d+)\-(\d+)\s(\d+:\d+:\d+)\]\s+\[.*?\]\s\[(smtp_\d+_tcp)\s(\d+)\]\s\[(\d+\.\d+\.\d+\.\d+:\d+)\]\sstat:\s(\d)\smails\=(\d+)\srecips\=(\d+)\sauth\=(.*?)\screds\=(.*?)\sbytes=(.*)/;
    my $RE_SMTPS = qr/^\[(\d+)\-(\d+)\-(\d+)\s(\d+:\d+:\d+)\]\s+\[.*?\]\s\[(smtps_\d+_tcp)\s(\d+)\]\s\[(\d+\.\d+\.\d+\.\d+:\d+)\]\sstat:\s(\d)\smails\=(\d+)\srecips\=(\d+)\sauth\=(.*?)\screds\=(.*?)\sbytes=(.*)/;
    my $RE_NTP = qr/^\[(\d+)\-(\d+)\-(\d+)\s(\d+:\d+:\d+)\]\s+\[.*?\]\s\[(ntp_\d+_udp)\s(\d+)\]\s\[(\d+\.\d+\.\d+\.\d+:\d+)\]\sstat:\s(\d)\sclient\=(.*?)\sserver\=(.*?)\ssecsdiff\=(\d+)/;
    my $RE_TFTP = qr/^\[(\d+)\-(\d+)\-(\d+)\s(\d+:\d+:\d+)\]\s+\[.*?\]\s\[(tftp_\d+_udp)\s(\d+)\]\s\[(\d+\.\d+\.\d+\.\d+:\d+)\]\sstat:\s(\d)\srequest\=(.*?)\smode\=(.*?)\sname\=(.*)/;
    my $RE_FTP = qr/^\[(\d+)\-(\d+)\-(\d+)\s(\d+:\d+:\d+)\]\s+\[.*?\]\s\[(ftp_\d+_tcp)\s(\d+)\]\s\[(\d+\.\d+\.\d+\.\d+:\d+)\]\sstat:\s(\d)\screated\=(\d+)\sdeleted\=(\d+)\sretrieved\=(\d+)\screds\=(.*)/;
    my $RE_FTPS = qr/^\[(\d+)\-(\d+)\-(\d+)\s(\d+:\d+:\d+)\]\s+\[.*?\]\s\[(ftps_\d+_tcp)\s(\d+)\]\s\[(\d+\.\d+\.\d+\.\d+:\d+)\]\sstat:\s(\d)\screated\=(\d+)\sdeleted\=(\d+)\sretrieved\=(\d+)\screds\=(.*)/;
    my $RE_HTTP = qr/^\[(\d+)\-(\d+)\-(\d+)\s(\d+:\d+:\d+)\]\s+\[.*?\]\s\[(http_\d+_tcp)\s(\d+)\]\s\[(\d+\.\d+\.\d+\.\d+:\d+)\]\sstat:\s(\d)\smethod=(.*?)\surl\=(.*?)\ssent\=(.*?)\spostdata\=(.*)/;
    my $RE_HTTPS = qr/^\[(\d+)\-(\d+)\-(\d+)\s(\d+:\d+:\d+)\]\s+\[.*?\]\s\[(https_\d+_tcp)\s(\d+)\]\s\[(\d+\.\d+\.\d+\.\d+:\d+)\]\sstat:\s(\d)\smethod=(.*?)\surl\=(.*?)\ssent\=(.*?)\spostdata\=(.*)/;
    my $RE_DNS = qr/^\[(\d+)\-(\d+)\-(\d+)\s(\d+:\d+:\d+)\]\s+\[.*?\]\s\[(dns_\d+_tcp_udp)\s(\d+)\]\s\[(\d+\.\d+\.\d+\.\d+)\]\sstat:\s(\d)\sqtype=(.*?)\sqclass\=(.*?)\sqname\=(.*)/;
    my $RE_Ident = qr/^\[(\d+)\-(\d+)\-(\d+)\s(\d+:\d+:\d+)\]\s+\[.*?\]\s\[(ident_\d+_tcp)\s(\d+)\]\s\[(\d+\.\d+\.\d+\.\d+:\d+)\]\sstat:\s(\d)\slport\=(\d+)\srport\=(\d+)/;

    my $RE_Daytime = qr/^\[(\d+)\-(\d+)\-(\d+)\s(\d+:\d+:\d+)\]\s+\[.*?\]\s\[(daytime_\d+_(tcp|udp))\s(\d+)\]\s\[(\d+\.\d+\.\d+\.\d+:\d+)\]\sstat:\s(\d)/;
    my $RE_Time = qr/^\[(\d+)\-(\d+)\-(\d+)\s(\d+:\d+:\d+)\]\s+\[.*?\]\s\[(time_\d+_(tcp|udp))\s(\d+)\]\s\[(\d+\.\d+\.\d+\.\d+:\d+)\]\sstat:\s(\d)/;
    my $RE_Discard = qr/^\[(\d+)\-(\d+)\-(\d+)\s(\d+:\d+:\d+)\]\s+\[.*?\]\s\[(discard_\d+_(tcp|udp))\s(\d+)\]\s\[(\d+\.\d+\.\d+\.\d+:\d+)\]\sstat:\s(\d)/;
    my $RE_Chargen = qr/^\[(\d+)\-(\d+)\-(\d+)\s(\d+:\d+:\d+)\]\s+\[.*?\]\s\[(chargen_\d+_(tcp|udp))\s(\d+)\]\s\[(\d+\.\d+\.\d+\.\d+:\d+)\]\sstat:\s(\d)/;
    my $RE_Quotd = qr/^\[(\d+)\-(\d+)\-(\d+)\s(\d+:\d+:\d+)\]\s+\[.*?\]\s\[(quotd_\d+_(tcp|udp))\s(\d+)\]\s\[(\d+\.\d+\.\d+\.\d+:\d+)\]\sstat:\s(\d)/;
    my $RE_Echo = qr/^\[(\d+)\-(\d+)\-(\d+)\s(\d+:\d+:\d+)\]\s+\[.*?\]\s\[(echo_\d+_(tcp|udp))\s(\d+)\]\s\[(\d+\.\d+\.\d+\.\d+:\d+)\]\sstat:\s(\d)/;
    my $RE_Finger = qr/^\[(\d+)\-(\d+)\-(\d+)\s(\d+:\d+:\d+)\]\s+\[.*?\]\s\[(finger_\d+_(tcp|udp))\s(\d+)\]\s\[(\d+\.\d+\.\d+\.\d+:\d+)\]\sstat:\s(\d)/;

    my $RE_SNAT = qr/^\[(\d+)\-(\d+)\-(\d+)\s(\d+:\d+:\d+)\]\s+\[.*?\]\s\[redirect\s(\d+)\]\s\[(\d+\.\d+\.\d+\.\d+:\d+)\]\sTranslating\s(tcp|udp|icmp)\sconnections\sfrom\shost\s(.*?)\,\ssource\schanged\sfrom\s(.*?)\sto\s(.*?)\,\sdestination\schanged\sfrom\s(.*?)\sto\s(.*?)(?:\,\sTTL\sset\sto\s(\d+))?\.$/i;
    my $RE_FWD = qr/^\[(\d+)\-(\d+)\-(\d+)\s(\d+:\d+:\d+)\]\s+\[.*?\]\s\[redirect\s(\d+)\]\s\[(\d+\.\d+\.\d+\.\d+:\d+)\]\sForwarding\s(tcp|udp|icmp)\sconnections\sfrom\shost\s(.*?)\sto\sdestination\s(.*?)(?:\,\sTTL\sset\sto\s(\d+))?\.$/i;
    my $RE_REDIR = qr/^\[(\d+)\-(\d+)\-(\d+)\s(\d+:\d+:\d+)\]\s+\[.*?\]\s\[redirect\s(\d+)\]\s\[(\d+\.\d+\.\d+\.\d+:[a-z0-9\-]+)\]\sRedirecting\s(tcp|udp|icmp)\sconnections\sfrom\shost\s(.*?)\,\sdestination\schanged\sfrom\s(.*?)\sto\s(.*?)(?:\,\sTTL\sset\sto\s(\d+))?\.$/i;

    my @stats_en = ();
    my @stats_de = ();
    my @report = ();
    my $lines = 0;
    my $real_date = "";
    my $fake_date = "";
    my $first_fake_date;
    my $last_fake_date = "";
    my $initial_delta = "";

    my $reportlang = &INetSim::Config::getConfigParameter("ReportLanguage");

    my $session = &INetSim::Config::getConfigParameter("SessionID");

    my $mainlogfilename = &INetSim::Config::getConfigParameter("MainLogfileName");
    my $sublogfilename = &INetSim::Config::getConfigParameter("SubLogfileName");

    if (! open(MAINLOG, "<$mainlogfilename")) {
	print STDOUT " Error creating report: Unable to open logfile '$mainlogfilename': $!\n";
	return;
    }

    while (<MAINLOG>) {
        s/[\r\n]+$//g;
        if ((/Session ID:\s+$session$/)) {
	    $real_date = <MAINLOG>;  # just skip listening IP
	    $real_date = <MAINLOG>;
	    $fake_date = <MAINLOG>;
	    $real_date =~ s/[\r\n]+$//g;
	    $fake_date =~ s/[\r\n]+$//g;
	    last;
	}
    }
    close MAINLOG;

    if (! open (SUBLOG, "<$sublogfilename")) {
	print STDOUT " Error creating report: Unable to open logfile '$sublogfilename': $!\n";
	return;
    }

    while (<SUBLOG>) {
        s/[\r\n]+$//g;
        if ((/\sstat\:\s\d/ || /\s\[redirect\s.*?\]\s/) && /\[$session\]/) {
            my $ttl = "";
            if ($_ =~ $RE_SNAT) {
                $ttl .= ", ttl: $13" if ($13);
                push (@stats_en, "$1-$2-$3 $4  Connection redirected, protocol: $7, destination: $11 => $12$ttl");
                push (@stats_de, "$3.$2.$1 $4  Verbindung umgeleitet, Protokoll: $1, Ziel: $11 => $12$ttl");
            }
            elsif ($_ =~ $RE_FWD) {
                $ttl .= ", ttl: $10" if ($10);
                push (@stats_en, "$1-$2-$3 $4  Connection redirected, protocol: $7, destination: $9 => $9$ttl");
                push (@stats_de, "$3.$2.$1 $4  Verbindung umgeleitet, Protokoll: $7, Ziel: $9 => $9$ttl");
            }
            elsif ($_ =~ $RE_REDIR) {
                $ttl .= ", ttl: $11" if ($11);
                push (@stats_en, "$1-$2-$3 $4  Connection redirected, protocol: $7, destination: $9 => $10$ttl");
                push (@stats_de, "$3.$2.$1 $4  Verbindung umgeleitet, Protokoll: $7, Ziel: $9 => $10$ttl");
            }
	    elsif ($_ =~ $RE_POP3) {
		push (@stats_en, "$1-$2-$3 $4  POP3 connection, mails loaded: $9, mails deleted: $10, authentication: $11, authentication data: $12") if ($8);
		push (@stats_de, "$3.$2.$1 $4  POP3 Verbindung, geladene Mails: $9, geloeschte Mails: $10, Authentisierung: $11, Anmeldedaten: $12") if ($8);
	    }
	    elsif ($_ =~ $RE_POP3S) {
		push (@stats_en, "$1-$2-$3 $4  POP3S connection, mails loaded: $9, mails deleted: $10, authentication: $11, authentication data: $12") if ($8);
		push (@stats_de, "$3.$2.$1 $4  POP3S Verbindung, geladene Mails: $9, geloeschte Mails: $10, Authentisierung: $11, Anmeldedaten: $12") if ($8);
	    }
	    elsif ($_ =~ $RE_SMTP) {
		push (@stats_en, "$1-$2-$3 $4  SMTP connection, mails sent: $9, number of recipients: $10, authentication: $11, authentication data: $12, bytes: $13") if ($8);
		push (@stats_de, "$3.$2.$1 $4  SMTP Verbindung, gesendete Mails: $9, Anzahl der Empfaenger: $10, Authentisierung: $11, Anmeldedaten: $12, Bytes: $13") if ($8);
            }
	    elsif ($_ =~ $RE_SMTPS) {
		push (@stats_en, "$1-$2-$3 $4  SMTPS connection, mails sent: $9, number of recipients: $10, authentication: $11, authentication data: $12, bytes: $13") if ($8);
		push (@stats_de, "$3.$2.$1 $4  SMTPS Verbindung, gesendete Mails: $9, Anzahl der Empfaenger: $10, Authentisierung: $11, Anmeldedaten: $12, Bytes: $13") if ($8);
            }
	    elsif ($_ =~ $RE_NTP) {
		push (@stats_en, "$1-$2-$3 $4  NTP connection, time received: $9, time sent: $10, difference: $11") if ($8);
		push (@stats_de, "$3.$2.$1 $4  NTP Verbindung, empfangene Zeit: $9, gesendete Zeit: $10, Differenz: $11") if ($8);
            }
	    elsif ($_ =~ $RE_TFTP) {
		push (@stats_en, "$1-$2-$3 $4  TFTP connection, request: $9, data mode: $10, file name: $11") if ($8);
		push (@stats_de, "$3.$2.$1 $4  TFTP Verbindung, Anfrage: $9, Datenmodus: $10, Dateiname: $11") if ($8);
	    }
	    elsif ($_ =~ $RE_FTP) {
		push (@stats_en, "$1-$2-$3 $4  FTP connection, created: $9, deleted: $10, retrieved: $11, authentication data: $12") if ($8);
		push (@stats_de, "$3.$2.$1 $4  FTP Verbindung, erstellt: $9, geloescht: $10, geladen: $11 Anmeldedaten: $12") if ($8);
            }
	    elsif ($_ =~ $RE_FTPS) {
		push (@stats_en, "$1-$2-$3 $4  FTPS connection, created: $9, deleted: $10, retrieved: $11, authentication data: $12") if ($8);
		push (@stats_de, "$3.$2.$1 $4  FTPS Verbindung, erstellt: $9, geloescht: $10, geladen: $11 Anmeldedaten: $12") if ($8);
            }
	    elsif ($_ =~ $RE_HTTP) {
	        if ($12) {
		    push (@stats_en, "$1-$2-$3 $4  HTTP connection, method: $9, URL: $10, file name: $12") if ($8);
		    push (@stats_de, "$3.$2.$1 $4  HTTP Verbindung, Methode: $9, URL: $10, Dateiname: $12") if ($8);
		}
		else {
		    push (@stats_en, "$1-$2-$3 $4  HTTP connection, method: $9, URL: $10, file name: $11") if ($8);
		    push (@stats_de, "$3.$2.$1 $4  HTTP Verbindung, Methode: $9, URL: $10, Dateiname: $11") if ($8);
		}
            }
	    elsif ($_ =~ $RE_HTTPS) {
	        if ($12) {
		    push (@stats_en, "$1-$2-$3 $4  HTTPS connection, method: $9, URL: $10, file name: $12") if ($8);
		    push (@stats_de, "$3.$2.$1 $4  HTTPS Verbindung, Methode: $9, URL: $10, Dateiname: $12") if ($8);
		}
		else {
		    push (@stats_en, "$1-$2-$3 $4  HTTPS connection, method: $9, URL: $10, file name: $11") if ($8);
		    push (@stats_de, "$3.$2.$1 $4  HTTPS Verbindung, Methode: $9, URL: $10, Dateiname: $11") if ($8);
		}
            }
	    elsif ($_ =~ $RE_DNS) {
		push (@stats_en, "$1-$2-$3 $4  DNS connection, type: $9, class: $10, requested name: $11") if ($8);
		push (@stats_de, "$3.$2.$1 $4  DNS Verbindung, Typ: $9, Klasse: $10, angefragter Name: $11") if ($8);
            }
	    elsif ($_ =~ $RE_Ident) {
		push (@stats_en, "$1-$2-$3 $4  Ident connection, local port: $9, remote port: $10") if ($8);
		push (@stats_de, "$3.$2.$1 $4  Ident Verbindung, lokaler Port: $9, entfernter Port: $10") if ($8);
	    }
	    elsif ($_ =~ $RE_Daytime) {
		push (@stats_en, "$1-$2-$3 $4  Daytime connection") if ($8);
		push (@stats_de, "$3.$2.$1 $4  Daytime Verbindung") if ($8);
	    }
	    elsif ($_ =~ $RE_Time) {
		push (@stats_en, "$1-$2-$3 $4  Time connection") if ($8);
		push (@stats_de, "$3.$2.$1 $4  Time Verbindung") if ($8);
	    }
	    elsif ($_ =~ $RE_Discard) {
		push (@stats_en, "$1-$2-$3 $4  Discard connection") if ($8);
		push (@stats_de, "$3.$2.$1 $4  Discard Verbindung") if ($8);
	    }
	    elsif ($_ =~ $RE_Chargen) {
		push (@stats_en, "$1-$2-$3 $4  Chargen connection") if ($8);
		push (@stats_de, "$3.$2.$1 $4  Chargen Verbindung") if ($8);
	    }
	    elsif ($_ =~ $RE_Quotd) {
		push (@stats_en, "$1-$2-$3 $4  Quotd connection") if ($8);
		push (@stats_de, "$3.$2.$1 $4  Quotd Verbindung") if ($8);
	    }
	    elsif ($_ =~ $RE_Echo) {
		push (@stats_en, "$1-$2-$3 $4  Echo connection") if ($8);
		push (@stats_de, "$3.$2.$1 $4  Echo Verbindung") if ($8);
	    }
	    elsif ($_ =~ $RE_Finger) {
		push (@stats_en, "$1-$2-$3 $4  Finger connection") if ($8);
		push (@stats_de, "$3.$2.$1 $4  Finger Verbindung") if ($8);
	    }
	    if (! $first_fake_date) {
	        $first_fake_date = $_;
	    }
	    $last_fake_date = $_;
	}
    }
    close SUBLOG;

    if (@stats_en && ($reportlang eq "en" || ! $reportlang)) {
        $real_date =~ s/^\[\d+\-\d+\-\d+\s\d+:\d+:\d+\]\s+Real\sDate\/Time:\s+(.*)$/$1/;
        $initial_delta = $fake_date;
        $fake_date =~ s/^\[\d+\-\d+\-\d+\s\d+:\d+:\d+\]\s+Fake\sDate\/Time:\s+(.*?)\s+\(Delta:\s[\-]?\d+\sseconds\)$/$1/;
        $initial_delta =~ s/^\[\d+\-\d+\-\d+\s\d+:\d+:\d+\]\s+Fake\sDate\/Time:\s+(.*?)\s+\(Delta:\s([\-]?\d+)\sseconds\)$/$2/;
        $first_fake_date =~ s/$RE_DTime_PID/$1-$2-$3 $4/;
        $last_fake_date =~ s/$RE_DTime_PID/$1-$2-$3 $4/;
        unshift (@stats_en, "$first_fake_date  First simulated date in log file") if ($first_fake_date);
        push (@stats_en, "$last_fake_date  Last simulated date in log file") if ($last_fake_date);
	$lines = @stats_en + 8;

        push (@report, "=== Report for session '$session' ===\n");
        push (@report, "Real start date            : $real_date");
        push (@report, "Simulated start date       : $fake_date");
	if ($initial_delta) {
	    push (@report, "Time difference on startup : $initial_delta seconds\n");
	}
	else {
	    push (@report, "Time difference on startup : none\n");
	}
        foreach (@stats_en) {
            push (@report, $_);
        }
        push (@report, "\n===");
    }

    if (@stats_de && $reportlang eq "de") {
        $real_date =~ s/^\[\d+\-\d+\-\d+\s\d+:\d+:\d+\]\s+Real\sDate\/Time:\s+(.*)$/$1/;
        $real_date =~ s/^(\d+)\-(\d+)\-(\d+)\s(\d+:\d+:\d+)/$3.$2.$1 $4/;
        $initial_delta = $fake_date;
        $fake_date =~ s/^\[\d+\-\d+\-\d+\s\d+:\d+:\d+\]\s+Fake\sDate\/Time:\s+(.*?)\s+\(Delta:\s[\-]?\d+\sseconds\)$/$1/;
        $fake_date =~ s/^(\d+)\-(\d+)\-(\d+)\s(\d+:\d+:\d+)/$3.$2.$1 $4/;
        $initial_delta =~ s/^\[\d+\-\d+\-\d+\s\d+:\d+:\d+\]\s+Fake\sDate\/Time:\s+(.*?)\s+\(Delta:\s([\-]?\d+)\sseconds\)$/$2/;
        $first_fake_date =~ s/$RE_DTime_PID/$3.$2.$1 $4/;
        $last_fake_date =~ s/$RE_DTime_PID/$3.$2.$1 $4/;
        unshift (@stats_de, "$first_fake_date  Erstes simuliertes Datum in der Log-Datei") if ($first_fake_date);
        push (@stats_de, "$last_fake_date  Letztes simuliertes Datum in der Log-Datei") if ($last_fake_date);
	$lines = @stats_de + 8;

        push (@report, "=== Report fuer Session '$session' ===\n");
        push (@report, "Reales Start-Datum          : $real_date");
        push (@report, "Simuliertes Start-Datum     : $fake_date");
	if ($initial_delta) {
	    push (@report, "Zeitverschiebung beim Start : $initial_delta Sekunden\n");
	}
	else {
	    push (@report, "Zeitverschiebung beim Start : keine\n");
	}
        foreach (@stats_de) {
            push (@report, $_);
        }
        push (@report, "\n===");
    }

    if (@report) {
	my $dummy = &INetSim::Config::getConfigParameter("ReportDir");
	$dummy =~ /^(.*)$/; # evil untaint!
	my $reportdir = $1;
	$dummy = $session;
	$dummy =~ /^(.*)$/; # evil untaint!
	$session = $1;
	my $reportfilename = $reportdir . "report.$session.txt";

        if (! open (REPORT, "> $reportfilename")) {
	    &INetSim::Log::MainLog(" Unable to open report file '$reportfilename' for writing: $!");
	}
	else {
	    foreach (@report) {
		print REPORT $_."\n";
	    }
	    close REPORT;
	    chmod 0440, $reportfilename;
	    my $uid = getpwnam("nobody");
	    my $gid = getgrnam("inetsim");
	    chown $uid, $gid, $reportfilename;
	    &INetSim::Log::MainLog(" Report written to '$reportfilename' ($lines lines)");
	}
    }
}




1;
#############################################################
#
# History:
#
# Version 0.50  (2013-08-14) th
# - fixed regexps to match new process name format
# - added date conversions for DE report language
# - changed some formatting
#
# Version 0.49  (2010-04-10) me
# - fix: regex for 'redirect' was wrong
#
# Version 0.48  (2009-09-04) me
# - added services POP3S, HTTPS and FTPS
#
# Version 0.47  (2009-09-03) me
# - added service SMTPS
#
# Version 0.46  (2008-09-05) me
# - changed all regular expressions again because of changed log format
# - changed regex and report text for service FTP
#
# Version 0.45  (2008-08-27) me
# - changed regular expressions because of changed log format
#
# Version 0.44  (2008-08-24) me
# - added service FTP
# - added use of config parameter 'ReportLanguage'
#
# Version 0.43  (2008-08-21) me
# - changed regex and report for smtp because of changes in SMTP.pm
#   (byte counter for received data)
#
# Version 0.42  (2008-08-10) me
# - changed regex and report for http because of changes in HTTP.pm
#
# Version 0.41  (2008-06-24) me
# - added reporting of redirected connections
#
# Version 0.40  (2007-12-07) me
# - added service finger
#
# Version 0.39  (2007-10-15) me
# - changed time format for English reports
#
# Version 0.38  (2007-10-14) me
# - added support for reports in English language
#
# Version 0.37  (2007-09-16) me
# - changed regex and report for smtp (authentication details added)
# - changed regex and report for pop3 (authentication details changed)
#
# Version 0.36  (2007-05-18) th
# - replaced die() call in check if report file successfully opened
# - change ownership of created reports to user "nobody" and group "inetsim"
#   and file mode to 0440
#
# Version 0.35  (2007-05-02) th
# - merged versions 0.34 and 0.34b
#
# Version 0.34b (2007-05-01) me
# - changed regular expression to match each port and protocol
#   for service xy
#
# Version 0.34  (2007-04-30) th
# - added logging of directory report was written to
#
# Version 0.33  (2007-04-27) th
# - use getConfigParameter
#
# Version 0.32  (2007-04-24) th
# - replaced die() calls if logfiles cannot be opened
#
# Version 0.31  (2007-04-22) th
# - replaced "request" with "method" for service http
#
# Version 0.3   (2007-04-21) me
# - rewrote module to use with INetSim
# - adding dns
# - adding tftp
# - adding http
# - adding ident
# - adding daytime
# - adding time
# - adding discard
# - adding chargen
# - adding quotd
# - adding echo
#
# Version 0.2   (2007-04-21) me
# - adding a small header with session id, initial delta, real and fake date
# - adding a line with last faked date
# - adding a line with first faked date
#
# Version 0.1   (2007-04-20) me
# - initial version (standalone)
# - adding pop3
# - adding smtp
# - adding ntp
#
#############################################################
