# -*- perl -*-
#
# INetSim::Config - INetSim configuration file parser
#
# (c)2007-2013 Thomas Hungenberg, Matthias Eckert
#
# Version 0.105 (2013-11-02)
#
# For history/changelog see bottom of this file.
#
#############################################################

package INetSim::Config;

use strict;
use warnings;
use Cwd;
use IPC::Shareable;


#############################################################
# Global / Default variables

my @SERVICES = qw/smtp pop3 http ftp ntp dns ident daytime_tcp daytime_udp time_tcp time_udp echo_tcp echo_udp discard_tcp discard_udp chargen_tcp chargen_udp quotd_tcp quotd_udp tftp autofaketime finger dummy_tcp dummy_udp syslog irc/;
my @SSLSERVICES = qw/smtps pop3s https ftps/;
my @ServicesToStart = ();
my @usedPorts = ();

# check for SSL support
eval { require IO::Socket::SSL; };
my $SSL = (! $@) ? 1 : 0;

# set BaseDir to current working directory
my $currentdir = cwd();
$currentdir =~ /^(.*)$/; # evil untaint!
my $logdir = $currentdir . "/log/";
my $datadir = $currentdir . "/data/";
my $reportdir = $currentdir . "/report/";

#############################################################
# Configuration Options

my %ConfigOptions;
my %shareopts = ( create => 1, exclusive => 0, mode => 0666, destroy => 1 );
tie %ConfigOptions, 'IPC::Shareable', "CNFG", { %shareopts } or die "unable to tie";

%ConfigOptions = (
		  SessionID => $$,
		  LogDir => $logdir,
		  MainLogfileName => $logdir . "main.log",
		  SubLogfileName => $logdir . "service.log",
		  DebugLogfileName => $logdir . "debug.log",
		  ConfigFileName => $currentdir . "/conf/inetsim.conf",
		  DataDir => $datadir,
		  CertDir => $datadir . "certs/",
		  ReportDir => $reportdir,
		  Debug => 0,

		  Faketime_Delta => 0,
		  Faketime_AutoDelay => 0,
		  Faketime_AutoIncrement => 3600,
		  Faketime_Max => 2147483647,

		  Default_BindAddress => "127.0.0.1",
		  Default_MaxChilds => 10,
		  Default_RunAsUser => 'nobody',
		  Default_RunAsGroup => 'inetsim',
		  Default_TimeOut => 120,

		  Default_KeyFileName => "default_key.pem",
		  Default_CrtFileName => "default_cert.pem",
		  Default_DHFileName => undef,

		  Create_Reports => 1,
		  ReportLanguage => "en",

		  Chargen_TCP_BindAddress => undef,
		  Chargen_TCP_BindPort => 19,
		  Chargen_TCP_MaxChilds => undef,
		  Chargen_TCP_RunAsUser => undef,
		  Chargen_TCP_RunAsGroup => undef,
		  Chargen_TCP_ServiceName => undef,

		  Chargen_UDP_BindAddress => undef,
		  Chargen_UDP_BindPort => 19,
		  Chargen_UDP_MaxChilds => undef,
		  Chargen_UDP_RunAsUser => undef,
		  Chargen_UDP_RunAsGroup => undef,
		  Chargen_UDP_ServiceName => undef,

		  Daytime_TCP_BindAddress => undef,
		  Daytime_TCP_BindPort => 13,
		  Daytime_TCP_MaxChilds => undef,
		  Daytime_TCP_RunAsUser => undef,
		  Daytime_TCP_RunAsGroup => undef,
		  Daytime_TCP_ServiceName => undef,

		  Daytime_UDP_BindAddress => undef,
		  Daytime_UDP_BindPort => 13,
		  Daytime_UDP_MaxChilds => undef,
		  Daytime_UDP_RunAsUser => undef,
		  Daytime_UDP_RunAsGroup => undef,
		  Daytime_UDP_ServiceName => undef,

		  Discard_TCP_BindAddress => undef,
		  Discard_TCP_BindPort => 9,
		  Discard_TCP_MaxChilds => undef,
		  Discard_TCP_RunAsUser => undef,
		  Discard_TCP_RunAsGroup => undef,
		  Discard_TCP_ServiceName => undef,

		  Discard_UDP_BindAddress => undef,
		  Discard_UDP_BindPort => 9,
		  Discard_UDP_MaxChilds => undef,
		  Discard_UDP_RunAsUser => undef,
		  Discard_UDP_RunAsGroup => undef,
		  Discard_UDP_ServiceName => undef,

		  DNS_BindAddress => undef,
		  DNS_BindPort => 53,
		  DNS_RunAsUser => undef,
		  DNS_RunAsGroup => undef,
		  DNS_MaxChilds => undef,
		  DNS_Default_IP => "127.0.0.1",
		  DNS_Default_Hostname => "www",
		  DNS_Default_Domainname => "inetsim.org",
		  DNS_Version => "INetSim DNS Server",
		  DNS_StaticHostToIP => {},
		  DNS_StaticIPToHost => {},
		  DNS_ServiceName => undef,

		  Echo_TCP_BindAddress => undef,
		  Echo_TCP_BindPort => 7,
		  Echo_TCP_MaxChilds => undef,
		  Echo_TCP_RunAsUser => undef,
		  Echo_TCP_RunAsGroup => undef,
		  Echo_TCP_ServiceName => undef,

		  Echo_UDP_BindAddress => undef,
		  Echo_UDP_BindPort => 7,
		  Echo_UDP_MaxChilds => undef,
		  Echo_UDP_RunAsUser => undef,
		  Echo_UDP_RunAsGroup => undef,
		  Echo_UDP_ServiceName => undef,

		  HTTP_BindAddress => undef,
		  HTTP_BindPort => 80,
		  HTTP_MaxChilds => undef,
		  HTTP_RunAsUser => undef,
		  HTTP_RunAsGroup => undef,
		  HTTP_DocumentRoot => $datadir . "http/wwwroot",
		  HTTP_MIMETypesFileName => $datadir . "http/mime.types",
		  HTTP_Version => "INetSim HTTP Server",
		  HTTP_FakeMode => 1,
		  HTTP_FakeFileDir => $datadir . "http/fakefiles",
		  HTTP_FakeFileExtToName => {},
		  HTTP_FakeFileExtToMIMEType => {},
		  HTTP_Default_FakeFileName => undef,
		  HTTP_Default_FakeFileMIMEType => undef,
		  HTTP_Static_FakeFilePathToName => {},
		  HTTP_Static_FakeFilePathToMIMEType => {},
		  HTTP_POSTDataDir => $datadir . "http/postdata",
		  HTTP_KeyFileName => undef,				# options added, because upgrade is possible (see RFC 2817)
		  HTTP_CrtFileName => undef,
		  HTTP_DHFileName => undef,
		  HTTP_ServiceName => undef,

		  HTTPS_BindAddress => undef,
		  HTTPS_BindPort => 443,
		  HTTPS_MaxChilds => undef,
		  HTTPS_RunAsUser => undef,
		  HTTPS_RunAsGroup => undef,
		  HTTPS_DocumentRoot => $datadir . "http/wwwroot",
		  HTTPS_MIMETypesFileName => $datadir . "http/mime.types",
		  HTTPS_Version => "INetSim HTTPs Server",
		  HTTPS_FakeMode => 1,
		  HTTPS_FakeFileDir => $datadir . "http/fakefiles",
		  HTTPS_FakeFileExtToName => {},
		  HTTPS_FakeFileExtToMIMEType => {},
		  HTTPS_Default_FakeFileName => undef,
		  HTTPS_Default_FakeFileMIMEType => undef,
		  HTTPS_Static_FakeFilePathToName => {},
		  HTTPS_Static_FakeFilePathToMIMEType => {},
		  HTTPS_POSTDataDir => $datadir . "http/postdata",
		  HTTPS_KeyFileName => undef,
		  HTTPS_CrtFileName => undef,
		  HTTPS_DHFileName => undef,
		  HTTPS_ServiceName => undef,

		  Ident_BindAddress => undef,
		  Ident_BindPort => 113,
		  Ident_MaxChilds => undef,
		  Ident_RunAsUser => undef,
		  Ident_RunAsGroup => undef,
		  Ident_ServiceName => undef,

		  NTP_BindAddress => undef,
		  NTP_BindPort => 123,
		  NTP_MaxChilds => undef,
		  NTP_RunAsUser => undef,
		  NTP_RunAsGroup => undef,
		  NTP_StrictChecks => 1,
		  NTP_Server_IP => "127.0.0.1",
		  NTP_ServiceName => undef,

		  POP3_BindAddress => undef,
		  POP3_BindPort => 110,
		  POP3_MaxChilds => undef,
		  POP3_RunAsUser => undef,
		  POP3_RunAsGroup => undef,
		  POP3_Version => "INetSim POP3 Server",
		  POP3_Banner => "INetSim POP3 Server ready",
		  POP3_Hostname => "pop3host",
		  POP3_MBOXDirName => $datadir . "pop3",
		  POP3_MBOXMaxMails => 10,
		  POP3_MBOXReRead => 180,
		  POP3_MBOXReBuild => 60,
		  POP3_EnableAPOP => 1,
		  POP3_EnableCapabilities => 1,
		  POP3_Capabilities => {},
		  POP3_AuthReversibleOnly => 0,
		  POP3_KeyFileName => undef,
		  POP3_CrtFileName => undef,
		  POP3_DHFileName => undef,
		  POP3_ServiceName => undef,

		  POP3S_BindAddress => undef,
		  POP3S_BindPort => 995,
		  POP3S_MaxChilds => undef,
		  POP3S_RunAsUser => undef,
		  POP3S_RunAsGroup => undef,
		  POP3S_Version => "INetSim POP3s Server",
		  POP3S_Banner => "INetSim POP3s Server ready",
		  POP3S_Hostname => "pop3host",
		  POP3S_MBOXDirName => $datadir . "pop3",
		  POP3S_MBOXMaxMails => 10,
		  POP3S_MBOXReRead => 180,
		  POP3S_MBOXReBuild => 60,
		  POP3S_EnableAPOP => 1,
		  POP3S_EnableCapabilities => 1,
		  POP3S_Capabilities => {},
		  POP3S_AuthReversibleOnly => 0,
		  POP3S_KeyFileName => undef,
		  POP3S_CrtFileName => undef,
		  POP3S_DHFileName => undef,
		  POP3S_ServiceName => undef,

		  Quotd_TCP_BindAddress => undef,
		  Quotd_TCP_BindPort => 17,
		  Quotd_TCP_MaxChilds => undef,
		  Quotd_TCP_RunAsUser => undef,
		  Quotd_TCP_RunAsGroup => undef,
		  Quotd_TCP_ServiceName => undef,

		  Quotd_UDP_BindAddress => undef,
		  Quotd_UDP_BindPort => 17,
		  Quotd_UDP_MaxChilds => undef,
		  Quotd_UDP_RunAsUser => undef,
		  Quotd_UDP_RunAsGroup => undef,
		  Quotd_QuotesFileName => $datadir . "quotd/quotd.txt",
		  Quotd_UDP_ServiceName => undef,

		  SMTP_BindAddress => undef,
		  SMTP_BindPort => 25,
		  SMTP_MaxChilds => undef,
		  SMTP_RunAsUser => undef,
		  SMTP_RunAsGroup => undef,
		  SMTP_Banner => "INetSim Mail Service ready.",
		  SMTP_FQDN_Hostname => "mail.inetsim.org",
		  SMTP_HELO_required => 0,
		  SMTP_Extended_SMTP => 1,
		  SMTP_Service_Extensions => {},
		  SMTP_MBOXFileName => $datadir . "smtp/smtp.mbox",
		  SMTP_AuthReversibleOnly => 0,
		  SMTP_AuthRequired => 0,
		  SMTP_KeyFileName => undef,
		  SMTP_CrtFileName => undef,
		  SMTP_DHFileName => undef,
		  SMTP_ServiceName => undef,

		  SMTPS_BindAddress => undef,
		  SMTPS_BindPort => 465,
		  SMTPS_MaxChilds => undef,
		  SMTPS_RunAsUser => undef,
		  SMTPS_RunAsGroup => undef,
		  SMTPS_Banner => "INetSim Mail Service ready.",
		  SMTPS_FQDN_Hostname => "mail.inetsim.org",
		  SMTPS_HELO_required => 0,
		  SMTPS_Extended_SMTP => 1,
		  SMTPS_Service_Extensions => {},
		  SMTPS_MBOXFileName => $datadir . "smtp/smtps.mbox",
		  SMTPS_AuthReversibleOnly => 0,
		  SMTPS_AuthRequired => 0,
		  SMTPS_KeyFileName => undef,
		  SMTPS_CrtFileName => undef,
		  SMTPS_DHFileName => undef,
		  SMTPS_ServiceName => undef,

		  TFTP_BindAddress => undef,
		  TFTP_BindPort => 69,
		  TFTP_MaxChilds => undef,
		  TFTP_RunAsUser => undef,
		  TFTP_RunAsGroup => undef,
		  TFTP_DocumentRoot => $datadir . "tftp/tftproot",
		  TFTP_UploadDir => $datadir . "tftp/upload",
		  TFTP_ServiceName => undef,
		  TFTP_AllowOverwrite => 0,
		  TFTP_EnableOptions => 1,
		  TFTP_Options => {},

		  Time_TCP_BindAddress => undef,
		  Time_TCP_BindPort => 37,
		  Time_TCP_MaxChilds => undef,
		  Time_TCP_RunAsUser => undef,
		  Time_TCP_RunAsGroup => undef,
		  Time_TCP_ServiceName => undef,

		  Time_UDP_BindAddress => undef,
		  Time_UDP_BindPort => 37,
		  Time_UDP_MaxChilds => undef,
		  Time_UDP_RunAsUser => undef,
		  Time_UDP_RunAsGroup => undef,
		  Time_UDP_ServiceName => undef,

		  Finger_BindAddress => undef,
		  Finger_BindPort => 79,
		  Finger_MaxChilds => undef,
		  Finger_RunAsUser => undef,
		  Finger_RunAsGroup => undef,
		  Finger_ServiceName => undef,
		  Finger_DataDirName => $datadir . "finger",

		  Dummy_TCP_BindAddress => undef,
		  Dummy_TCP_BindPort => 1,
		  Dummy_TCP_MaxChilds => undef,
		  Dummy_TCP_RunAsUser => undef,
		  Dummy_TCP_RunAsGroup => undef,
		  Dummy_TCP_ServiceName => undef,
		  Dummy_Banner => "220 ESMTP FTP +OK POP3 200 OK",
		  Dummy_BannerWait => 5,

		  Dummy_UDP_BindAddress => undef,
		  Dummy_UDP_BindPort => 1,
		  Dummy_UDP_MaxChilds => undef,
		  Dummy_UDP_RunAsUser => undef,
		  Dummy_UDP_RunAsGroup => undef,
		  Dummy_UDP_ServiceName => undef,

		  Redirect_Enabled => 0,
		  Redirect_UnknownServices => 1,
		  Redirect_ExternalAddress => undef,
		  Redirect_ChangeTTL => 0,
		  Redirect_StaticRules => {},
		  Redirect_IgnoreBootp => 0,
		  Redirect_IgnoreNetbios => 0,
		  Redirect_ICMP_Timestamp => 1,

		  FTP_BindAddress => undef,
		  FTP_BindPort => 21,
		  FTP_DataPort => 20,
		  FTP_MaxChilds => undef,
		  FTP_RunAsUser => undef,
		  FTP_RunAsGroup => undef,
		  FTP_Version => "INetSim FTP Server",
		  FTP_Banner => "INetSim FTP Service ready.",
		  FTP_DocumentRoot => $datadir . "ftp/ftproot",
		  FTP_UploadDir => $datadir . "ftp/upload",
		  FTP_RecursiveDelete => 0,
		  FTP_KeyFileName => undef,
		  FTP_CrtFileName => undef,
		  FTP_DHFileName => undef,
		  FTP_ServiceName => undef,

		  FTPS_BindAddress => undef,
		  FTPS_BindPort => 990,
		  FTPS_DataPort => 989,
		  FTPS_MaxChilds => undef,
		  FTPS_RunAsUser => undef,
		  FTPS_RunAsGroup => undef,
		  FTPS_Version => "INetSim FTPs Server",
		  FTPS_Banner => "INetSim FTP Service ready.",
		  FTPS_DocumentRoot => $datadir . "ftp/ftproot",
		  FTPS_UploadDir => $datadir . "ftp/upload",
		  FTPS_RecursiveDelete => 0,
		  FTPS_KeyFileName => undef,
		  FTPS_CrtFileName => undef,
		  FTPS_DHFileName => undef,
		  FTPS_ServiceName => undef,

		  Syslog_BindAddress => undef,
		  Syslog_BindPort => 514,
		  Syslog_MaxChilds => undef,
		  Syslog_RunAsUser => undef,
		  Syslog_RunAsGroup => undef,
		  Syslog_ServiceName => undef,
		  Syslog_AcceptInvalid => 0,
		  Syslog_TrimMaxLength => 0,

		  IRC_BindAddress => undef,
		  IRC_BindPort => 6667,
		  IRC_MaxChilds => undef,
		  IRC_RunAsUser => undef,
		  IRC_RunAsGroup => undef,
		  IRC_FQDN_Hostname => "irc.inetsim.org",
		  IRC_Version => "INetSim IRC Server",
		  IRC_ServiceName => undef,

		  IRCS_BindAddress => undef,
		  IRCS_BindPort => 994,
		  IRCS_MaxChilds => undef,
		  IRCS_RunAsUser => undef,
		  IRCS_RunAsGroup => undef,
		  IRCS_FQDN_Hostname => "irc.inetsim.org",
		  IRCS_Version => "INetSim IRCs Server",
		  IRCS_ServiceName => undef
		  );


#############################################################
# Local variables

my $lineNumber = 0;

# compiled regular expressions for matching strings
my $RE_signedInt = qr/^[-]{0,1}[\d]+$/;
my $RE_unsignedInt = qr/^[\d]+$/;
my $RE_printable = qr/^[\x20-\x7e]+$/;
my $RE_validIP = qr/^(([01]?[0-9][0-9]?|2[0-4][0-9]|25[0-5])\.){3}([01]?[0-9][0-9]?|2[0-4][0-9]|25[0-5])$/;
my $RE_validHostname = qr/^[a-zA-Z0-9]([-a-zA-Z0-9]*[a-zA-Z0-9]|)$/;
my $RE_validDomainname = qr/^([a-zA-Z0-9]([-a-zA-Z0-9]*[a-zA-Z0-9]|)\.)*[a-zA-Z]+$/;
my $RE_validFQDNHostname = qr/^([a-zA-Z0-9]([-a-zA-Z0-9]*[a-zA-Z0-9]|)\.)+[a-zA-Z]+$/;
my $RE_validFilename = qr/^[a-zA-Z0-9\.\-\_]+$/;


#############################################################

sub parse_config {

    my $log_dir = &INetSim::CommandLine::getCommandLineOption("log_dir");
    if(defined $log_dir) {
	&setConfigParameter("LogDir", $log_dir);
	&setConfigParameter("MainLogfileName", $log_dir . "main.log");
	&setConfigParameter("SubLogfileName", $log_dir . "service.log");
	&setConfigParameter("DebugLogfileName", $log_dir . "debug.log");
    }

    my $data_dir = &INetSim::CommandLine::getCommandLineOption("data_dir");
    if(defined $data_dir) {
	&setConfigParameter("DataDir", $data_dir);
	#
	&setConfigParameter("CertDir", $data_dir . "certs/");
	#
	&setConfigParameter("HTTP_DocumentRoot", $data_dir . "http/wwwroot");
	&setConfigParameter("HTTP_MIMETypesFileName", $data_dir . "http/mime.types");
	&setConfigParameter("HTTP_FakeFileDir", $data_dir . "http/fakefiles");
	&setConfigParameter("HTTP_POSTDataDir", $data_dir . "http/postdata");
	#
	&setConfigParameter("HTTPS_DocumentRoot", $data_dir . "http/wwwroot");
	&setConfigParameter("HTTPS_MIMETypesFileName", $data_dir . "http/mime.types");
	&setConfigParameter("HTTPS_FakeFileDir", $data_dir . "http/fakefiles");
	&setConfigParameter("HTTPS_POSTDataDir", $data_dir . "http/postdata");
	#
	&setConfigParameter("POP3_MBOXDirName", $data_dir . "pop3");
	#
	&setConfigParameter("POP3S_MBOXDirName", $data_dir . "pop3");
	#
	&setConfigParameter("Quotd_QuotesFileName", $data_dir . "quotd/quotd.txt");
	#
	&setConfigParameter("SMTP_MBOXFileName", $data_dir . "smtp/smtp.mbox");
	#
	&setConfigParameter("SMTPS_MBOXFileName", $data_dir . "smtp/smtps.mbox");
	#
	&setConfigParameter("TFTP_DocumentRoot", $data_dir . "tftp/tftproot");
	&setConfigParameter("TFTP_UploadDir", $data_dir . "tftp/upload");
	#
	&setConfigParameter("Finger_DataDirName", $data_dir . "finger");
	#
	&setConfigParameter("FTP_DocumentRoot", $data_dir . "ftp/ftproot");
	&setConfigParameter("FTP_UploadDir", $data_dir . "ftp/upload");
	#
	&setConfigParameter("FTPS_DocumentRoot", $data_dir . "ftp/ftproot");
	&setConfigParameter("FTPS_UploadDir", $data_dir . "ftp/upload");
    }

    my $report_dir = &INetSim::CommandLine::getCommandLineOption("report_dir");
    if(defined $report_dir) {
	&setConfigParameter("ReportDir", $report_dir);
    }

    # Initialize logfiles
    &INetSim::Log::init();

    &INetSim::Log::MainLog("Using log directory:      " . &getConfigParameter("LogDir"));
    &INetSim::Log::MainLog("Using data directory:     " . &getConfigParameter("DataDir"));
    &INetSim::Log::MainLog("Using report directory:   " . &getConfigParameter("ReportDir"));

    my @args = ();
    my %dns_statichosttoip = ();
    my %dns_staticiptohost = ();
    my %http_fakefile_exttoname = ();
    my %http_fakefile_exttomimetype = ();
    my %http_static_fakefile_pathtoname = ();
    my %http_static_fakefile_pathtomimetype = ();
    my %https_fakefile_exttoname = ();
    my %https_fakefile_exttomimetype = ();
    my %https_static_fakefile_pathtoname = ();
    my %https_static_fakefile_pathtomimetype = ();
    my %redirect_static_rules = ();
    my %smtp_service_extensions = ();
    my %smtps_service_extensions = ();
    my %pop3_capabilities = ();
    my %pop3s_capabilities = ();
    my %tftp_options = ();

    my $configfilename = &INetSim::CommandLine::getCommandLineOption("config");
    if (defined $configfilename) {
	if ($configfilename =~ /^\//) {
	    &setConfigParameter("ConfigFileName", $configfilename);
	}
	else {
	    &setConfigParameter("ConfigFileName", $currentdir . "/" . $configfilename);
	}
    }
    else {
	$configfilename = &getConfigParameter("ConfigFileName");
    }

    &INetSim::Log::MainLog("Using configuration file: " . &getConfigParameter("ConfigFileName"));

    open (CONFIGFILE, "<$configfilename") or &INetSim::error_exit("Unable to open configuration file '$configfilename': $!", 1);

    &INetSim::Log::MainLog("Parsing configuration file.");

    while (<CONFIGFILE>) {
	$lineNumber++;
	# remove whitespaces at beginning of line
	s/^[\s]+//g;
	# remove cr/lf from end of line
	s/[\r\n]+$//g;
	if (!length()) {
	    # skip blank line
	    next;
	}
	elsif (/^[\#]/) {
	    next; # skip comment
	}
	else {
	    @args = &splitline($_);

	    #################################################
	    # start_service
	    if ($args[0] =~ /^start_service$/i) {
		my $serviceName = lc($args[1]);
		if (grep(/^$serviceName$/,@SERVICES) == 1) {
		    if (grep/^$serviceName$/, @ServicesToStart) {
			&config_warn("Service '$serviceName' already listed");
		    }
		    else {
			push (@ServicesToStart, $serviceName);
		    }
		}
		elsif (grep(/^$serviceName$/,@SSLSERVICES) == 1) {
		    if (grep/^$serviceName$/, @ServicesToStart) {
			&config_warn("Service '$serviceName' already listed");
		    }
		    elsif (! $SSL) {
			&config_warn("Service '$serviceName' listed, but no SSL support");
		    }
		    else {
			push (@ServicesToStart, $serviceName);
		    }
		}
		else {
		    &config_warn("Unknown service name '$serviceName'");
		}
	    }


	    #################################################
	    # Create_Reports
	    elsif ($args[0] =~ /^create_reports$/i) {
		if ($args[1] =~ /^yes$/i) {
		    &setConfigParameter("Create_Reports", 1);
		}
		elsif ($args[1] =~ /^no$/i) {
		    &setConfigParameter("Create_Reports", 0);
		}
		else {
		    &config_error("Invalid argument '$args[1]'");
		}
	    }


	    #################################################
	    # ReportLanguage
	    elsif ($args[0] =~ /^report_language$/i) {
	        if ($args[1] =~ /^(de|en)$/i) {
	            &setConfigParameter("ReportLanguage", lc($args[1]));
	        }
	        else {
	            &config_error("'$args[1]' is not a valid language");
	        }
	    }


	    #################################################
	    # Faketime
	    elsif ($args[0] =~ /^faketime_init_delta$/i) {
		if ($args[1] =~ $RE_signedInt) {
		    my $cur_secs = time();
		    my $delta = $args[1];
		    my $faketimemax = &getConfigParameter("Faketime_Max");
		    if (($cur_secs + $delta) > $faketimemax) {
			&config_error("Fake time exceeds maximum system time");
		    }
		    elsif (($cur_secs + $delta) < 0 ) {
			&config_error("Fake time init delta too small");
		    }
		    &setConfigParameter("Faketime_Delta", $delta);
		}
		else {
		    &config_error("'$args[1]' is not numeric");
                }
	    }


	    #################################################
	    # Faketime_AutoDelay
	    elsif ($args[0] =~ /^faketime_auto_delay$/i) {
		if (($args[1] =~ $RE_unsignedInt) && int($args[1] >= 0) && int($args[1] < 86401)) {
		    &setConfigParameter("Faketime_AutoDelay", int($args[1]));
		}
		else {
		    &config_error("'$args[1]' is not an integer value of range [0..86400]");
		}
	    }


	    #################################################
	    # Faketime_AutoIncrement
	    elsif ($args[0] =~ /^faketime_auto_increment$/i) {
		if ($args[1] =~ $RE_signedInt && int($args[1] > -31536001) && int($args[1] < 31536001)) {
		    &setConfigParameter("Faketime_AutoIncrement", int($args[1]));
		}
		else {
		    &config_error("'$args[1]' is not an integer value of range [-31536000..31536000]");
		}
	    }

	    # service_max_childs
	    elsif ($args[0] =~ /^service_max_childs$/i) {
		if (($args[1] =~ $RE_unsignedInt) && int($args[1] > 0) && int($args[1] < 31)) {
		    &setConfigParameter("Default_MaxChilds", int($args[1]));
		}
		else {
		    &config_error("'$args[1]' is not an integer value of range [1..30]");
		}
	    }


	    # service_bind_address
	    elsif ($args[0] =~ /^service_bind_address$/i) {
#		if ($args[1] =~ /^0.0.0.0$/) {
#		    &config_error("service_bind_address '0.0.0.0' not allowed");
#		}
		($args[1] =~ $RE_validIP) ? &setConfigParameter("Default_BindAddress", $args[1]) : &config_error("'$args[1]' is not a valid IP address");
	    }


	    # service_run_as_user
	    elsif ($args[0] =~ /^service_run_as_user$/i) {
		my $user = $args[1];
		if ($args[1] !~ $RE_printable) {
		    &config_error("'$user' is not a valid username");
		}
		else {
		    my $uid = getpwnam($user);
		    if (defined $uid) {
			&setConfigParameter("Default_RunAsUser", $user);
		    }
		    else {
			&config_error("User '$user' does not exist on this system");
		    }
		}
	    }


	    # service_timeout
	    elsif ($args[0] =~ /^service_timeout$/i) {
                if ($args[1] =~ $RE_unsignedInt && int($args[1] > 0) && int($args[1] < 601)) {
                    &setConfigParameter("Default_TimeOut", int($args[1]));
                }
                else {
                    &config_error("'$args[1]' is not an integer value of range [1..600]");
                }
            }


	    #################################################
	    # Chargen
	    #################################################

	    # Chargen_BindPort
	    elsif ($args[0] =~ /^chargen_bind_port$/i) {
		if (($args[1] =~ /[\d]+/) && ($args[1] > 0) && ($args[1] < 65535)) {
		    &setConfigParameter("Chargen_TCP_BindPort", $args[1]);
		    &setConfigParameter("Chargen_UDP_BindPort", $args[1]);
		}
		else {
		    &config_error("'$args[1]' is not a valid port number");
		}
	    }


	    #################################################
	    # Daytime
	    #################################################

	    # Daytime_BindPort
	    elsif ($args[0] =~ /^daytime_bind_port$/i) {
		if (($args[1] =~ /[\d]+/) && ($args[1] > 0) && ($args[1] < 65535)) {
		    &setConfigParameter("Daytime_TCP_BindPort", $args[1]);
		    &setConfigParameter("Daytime_UDP_BindPort", $args[1]);
		}
		else {
		    &config_error("'$args[1]' is not a valid port number");
		}
	    }


	    #################################################
	    # Discard
	    #################################################

	    # Discard_BindPort
	    elsif ($args[0] =~ /^discard_bind_port$/i) {
		if (($args[1] =~ /[\d]+/) && ($args[1] > 0) && ($args[1] < 65535)) {
		    &setConfigParameter("Discard_TCP_BindPort", $args[1]);
		    &setConfigParameter("Discard_UDP_BindPort", $args[1]);
		}
		else {
		    &config_error("'$args[1]' is not a valid port number");
		}
	    }


	    #################################################
	    # DNS
	    #################################################

	    # DNS_BindPort
	    elsif ($args[0] =~ /^dns_bind_port$/i) {
		(($args[1] =~ /[\d]+/) && ($args[1] > 0) && ($args[1] < 65535)) ? &setConfigParameter("DNS_BindPort", $args[1]) : &config_error("'$args[1]' is not a valid port number");
	    }

	    # DNS_Default_IP
	    elsif ($args[0] =~ /^dns_default_ip$/i) {
		($args[1] =~ $RE_validIP) ? &setConfigParameter("DNS_Default_IP", $args[1]) : &config_error("'$args[1]' is not a valid IP address");
	    }

	    # DNS_Default_Hostname
	    elsif ($args[0] =~ /^dns_default_hostname$/i) {
		($args[1] =~ $RE_validHostname) ? &setConfigParameter("DNS_Default_Hostname", $args[1]) : &config_error("'$args[1]' is not a valid hostname");
	    }

	    # DNS_Default_Domainname
	    elsif ($args[0] =~ /^dns_default_domainname$/i) {
		($args[1] =~ $RE_validDomainname) ? &setConfigParameter("DNS_Default_Domainname", $args[1]) : &config_error("'$args[1]' is not a valid domainname");
	    }

	    # DNS_Version
	    elsif ($args[0] =~ /^dns_version$/i) {
		($args[1] =~ $RE_printable) ? &setConfigParameter("DNS_Version", $args[1]) : &config_error("'$args[1]' is not a valid version string");
	    }

	    # DNS_Static
	    elsif ($args[0] =~ /^dns_static$/i) {
		if ($args[1] !~ $RE_validFQDNHostname) {
		    &config_error("'$args[1]' is not a valid FQDN hostname");
		}
		elsif ($args[2] !~ $RE_validIP) {
		    &config_error("'$args[2]' is not a valid IP address");
		}
		else {
		    $dns_statichosttoip{lc($args[1])} = $args[2];
		    my @ip = split(/\./, $args[2]);
		    my $reverse_ip = $ip[3] . "." . $ip[2] . "." . $ip[1] . "." . $ip[0] . ".in-addr.arpa";
		    $dns_staticiptohost{$reverse_ip} = lc($args[1]);
		}
	    }

	    #################################################
	    # Echo
	    #################################################

	    # Echo_BindPort
	    elsif ($args[0] =~ /^echo_bind_port$/i) {
		if (($args[1] =~ /[\d]+/) && ($args[1] > 0) && ($args[1] < 65535)) {
		    &setConfigParameter("Echo_TCP_BindPort", $args[1]);
		    &setConfigParameter("Echo_UDP_BindPort", $args[1]);
		}
		else {
		    &config_error("'$args[1]' is not a valid port number");
		}
	    }


	    #################################################
	    # Ident
	    #################################################

	    # Ident_BindPort
	    elsif ($args[0] =~ /^ident_bind_port$/i) {
		(($args[1] =~ /[\d]+/) && ($args[1] > 0) && ($args[1] < 65535)) ? &setConfigParameter("Ident_BindPort", $args[1]) : &config_error("'$args[1]' is not a valid port number");
	    }


	    #################################################
	    # HTTP
	    #################################################

	    # HTTP_BindPort
	    elsif ($args[0] =~ /^http_bind_port$/i) {
		(($args[1] =~ /[\d]+/) && ($args[1] > 0) && ($args[1] < 65535)) ? &setConfigParameter("HTTP_BindPort", $args[1]) : &config_error("'$args[1]' is not a valid port number");
	    }

	    # HTTP_Version
	    elsif ($args[0] =~ /^http_version$/i) {
		($args[1] =~ $RE_printable) ? &setConfigParameter("HTTP_Version", $args[1]) : &config_error("'$args[1]' is not a valid HTTP version string");
	    }

	    # HTTP_FakeMode
	    elsif ($args[0] =~ /^http_fakemode$/i) {
		if ($args[1] =~ /^yes$/i) {
		    &setConfigParameter("HTTP_FakeMode", 1);
		}
		elsif ($args[1] =~ /^no$/i) {
		    &setConfigParameter("HTTP_FakeMode", 0);
		}
		else {
		    &config_error("Invalid argument '$args[1]'");
		}
	    }

	    # HTTP_FakeFile
	    elsif ($args[0] =~ /^http_fakefile$/i) {
		if (!$args[3]) {
		    &config_error("missing argument for http_fakefile");
		}
		elsif ($args[1] !~ /^[a-zA-Z0-9]+$/) {
		    &config_error("'$args[1]' is not a valid extension");
		}
		elsif ($args[2] !~ $RE_validFilename) {
		    &config_error("'$args[2]' is not a valid filename");
		}
		elsif ($args[3] !~ /^[a-zA-Z0-9\+\-\/]+$/) {
		    &config_error("'$args[3]' is not a valid MIME type");
		}
		else {
		    $http_fakefile_exttoname{$args[1]} = $args[2];
		    $http_fakefile_exttomimetype{$args[1]} = $args[3];
		}
	    }

	    # HTTP_Default_FakeFile
	    elsif ($args[0] =~ /^http_default_fakefile$/i) {
		if (!$args[2]) {
		    &config_error("missing argument for http_default_fakefile");
		}
		elsif ($args[1] !~ $RE_validFilename) {
		    &config_error("'$args[1]' is not a valid filename");
		}
		elsif ($args[2] !~ /^[a-zA-Z0-9\+\-\/]+$/) {
		    &config_error("'$args[2]' is not a valid MIME type");
		}
		else {
		    &setConfigParameter("HTTP_Default_FakeFileName", $args[1]);
		    &setConfigParameter("HTTP_Default_FakeFileMIMEType", $args[2]);
		}
	    }

	    # HTTP_Static_FakeFile
	    elsif ($args[0] =~ /^http_static_fakefile$/i) {
		if (!$args[3]) {
		    &config_error("missing argument for http_static_fakefile");
		}
		elsif (($args[1] !~ /^\/[[:graph:]]+$/) || ($args[1] =~ /\?/)) {
		    &config_error("'$args[1]' is not a valid path");
		}
		elsif ($args[2] !~ $RE_validFilename) {
		    &config_error("'$args[2]' is not a valid filename");
		}
		elsif ($args[3] !~ /^[a-zA-Z0-9\+\-\/]+$/) {
		    &config_error("'$args[3]' is not a valid MIME type");
		}
		else {
		    $http_static_fakefile_pathtoname{$args[1]} = $args[2];
		    $http_static_fakefile_pathtomimetype{$args[1]} = $args[3];
		}
	    }

	    # HTTP_KeyFileName
	    elsif ($args[0] =~ /^http_ssl_keyfile$/i) {
		if (! $args[1]) {
		    &config_error("missing argument for http_ssl_keyfile");
		}
		elsif ($args[1] !~ $RE_validFilename) {
		    &config_error("'$args[1]' is not a valid filename");
		}
		else {
		    &setConfigParameter("HTTP_KeyFileName", $args[1]);
		}
	    }

	    # HTTP_CrtFileName
	    elsif ($args[0] =~ /^http_ssl_certfile$/i) {
		if (! $args[1]) {
		    &config_error("missing argument for http_ssl_certfile");
		}
		elsif ($args[1] !~ $RE_validFilename) {
		    &config_error("'$args[1]' is not a valid filename");
		}
		else {
		    &setConfigParameter("HTTP_CrtFileName", $args[1]);
		}
	    }

	    # HTTP_DHFileName
	    elsif ($args[0] =~ /^http_ssl_dhfile$/i) {
		if (! $args[1]) {
		    &config_error("missing argument for http_ssl_dhfile");
		}
		elsif ($args[1] !~ $RE_validFilename) {
		    &config_error("'$args[1]' is not a valid filename");
		}
		else {
		    &setConfigParameter("HTTP_DHFileName", $args[1]);
		}
	    }


	    #################################################
	    # HTTPS
	    #################################################

	    # HTTPS_BindPort
	    elsif ($args[0] =~ /^https_bind_port$/i) {
		(($args[1] =~ /[\d]+/) && ($args[1] > 0) && ($args[1] < 65535)) ? &setConfigParameter("HTTPS_BindPort", $args[1]) : &config_error("'$args[1]' is not a valid port number");
	    }

	    # HTTPS_Version
	    elsif ($args[0] =~ /^https_version$/i) {
		($args[1] =~ $RE_printable) ? &setConfigParameter("HTTPS_Version", $args[1]) : &config_error("'$args[1]' is not a valid HTTP version string");
	    }

	    # HTTPS_FakeMode
	    elsif ($args[0] =~ /^https_fakemode$/i) {
		if ($args[1] =~ /^yes$/i) {
		    &setConfigParameter("HTTPS_FakeMode", 1);
		}
		elsif ($args[1] =~ /^no$/i) {
		    &setConfigParameter("HTTPS_FakeMode", 0);
		}
		else {
		    &config_error("Invalid argument '$args[1]'");
		}
	    }

	    # HTTPS_FakeFile
	    elsif ($args[0] =~ /^https_fakefile$/i) {
		if (!$args[3]) {
		    &config_error("missing argument for https_fakefile");
		}
		elsif ($args[1] !~ /^[a-zA-Z0-9]+$/) {
		    &config_error("'$args[1]' is not a valid extension");
		}
		elsif ($args[2] !~ $RE_validFilename) {
		    &config_error("'$args[2]' is not a valid filename");
		}
		elsif ($args[3] !~ /^[a-zA-Z0-9\+\-\/]+$/) {
		    &config_error("'$args[3]' is not a valid MIME type");
		}
		else {
		    $https_fakefile_exttoname{$args[1]} = $args[2];
		    $https_fakefile_exttomimetype{$args[1]} = $args[3];
		}
	    }

	    # HTTPS_Default_FakeFile
	    elsif ($args[0] =~ /^https_default_fakefile$/i) {
		if (!$args[2]) {
		    &config_error("missing argument for https_default_fakefile");
		}
		elsif ($args[1] !~ $RE_validFilename) {
		    &config_error("'$args[1]' is not a valid filename");
		}
		elsif ($args[2] !~ /^[a-zA-Z0-9\+\-\/]+$/) {
		    &config_error("'$args[2]' is not a valid MIME type");
		}
		else {
		    &setConfigParameter("HTTPS_Default_FakeFileName", $args[1]);
		    &setConfigParameter("HTTPS_Default_FakeFileMIMEType", $args[2]);
		}
	    }

	    # HTTPS_Static_FakeFile
	    elsif ($args[0] =~ /^https_static_fakefile$/i) {
		if (!$args[3]) {
		    &config_error("missing argument for https_static_fakefile");
		}
		elsif (($args[1] !~ /^\/[[:graph:]]+$/) || ($args[1] =~ /\?/)) {
		    &config_error("'$args[1]' is not a valid path");
		}
		elsif ($args[2] !~ $RE_validFilename) {
		    &config_error("'$args[2]' is not a valid filename");
		}
		elsif ($args[3] !~ /^[a-zA-Z0-9\+\-\/]+$/) {
		    &config_error("'$args[3]' is not a valid MIME type");
		}
		else {
		    $https_static_fakefile_pathtoname{$args[1]} = $args[2];
		    $https_static_fakefile_pathtomimetype{$args[1]} = $args[3];
		}
	    }

	    # HTTPS_KeyFileName
	    elsif ($args[0] =~ /^https_ssl_keyfile$/i) {
		if (! $args[1]) {
		    &config_error("missing argument for https_ssl_keyfile");
		}
		elsif ($args[1] !~ $RE_validFilename) {
		    &config_error("'$args[1]' is not a valid filename");
		}
		else {
		    &setConfigParameter("HTTPS_KeyFileName", $args[1]);
		}
	    }

	    # HTTPS_CrtFileName
	    elsif ($args[0] =~ /^https_ssl_certfile$/i) {
		if (! $args[1]) {
		    &config_error("missing argument for https_ssl_certfile");
		}
		elsif ($args[1] !~ $RE_validFilename) {
		    &config_error("'$args[1]' is not a valid filename");
		}
		else {
		    &setConfigParameter("HTTPS_CrtFileName", $args[1]);
		}
	    }

	    # HTTPS_DHFileName
	    elsif ($args[0] =~ /^https_ssl_dhfile$/i) {
		if (! $args[1]) {
		    &config_error("missing argument for https_ssl_dhfile");
		}
		elsif ($args[1] !~ $RE_validFilename) {
		    &config_error("'$args[1]' is not a valid filename");
		}
		else {
		    &setConfigParameter("HTTPS_DHFileName", $args[1]);
		}
	    }


	    #################################################
	    # NTP
	    #################################################

	    # NTP_BindPort
	    elsif ($args[0] =~ /^ntp_bind_port$/i) {
		(($args[1] =~ /[\d]+/) && ($args[1] > 0) && ($args[1] < 65535)) ? &setConfigParameter("NTP_BindPort", $args[1]) : &config_error("'$args[1]' is not a valid port number");
	    }

	    # NTP_Server_IP
	    elsif ($args[0] =~ /^ntp_server_ip$/i) {
		if ($args[1] =~ /^0.0.0.0$/) {
		    &config_error("ntp_server_ip '0.0.0.0' not allowed");
		}
		($args[1] =~ $RE_validIP) ? &setConfigParameter("NTP_Server_IP", $args[1]) : &config_error("'$args[1]' is not a valid IP address");
	    }

	    # NTP_StrictChecks
	    elsif ($args[0] =~ /^ntp_strict_checks$/i) {
                if ($args[1] =~ /^yes$/i) {
                    &setConfigParameter("NTP_StrictChecks", 1);
                }
                elsif ($args[1] =~ /^no$/i) {
                    &setConfigParameter("NTP_StrictChecks", 0);
                }
                else {
                    &config_error("Invalid argument '$args[1]'");
                }
	    }


	    #################################################
	    # POP3
	    #################################################

	    # POP3_BindPort
	    elsif ($args[0] =~ /^pop3_bind_port$/i) {
		(($args[1] =~ /[\d]+/) && ($args[1] > 0) && ($args[1] < 65535)) ? &setConfigParameter("POP3_BindPort", $args[1]) : &config_error("'$args[1]' is not a valid port number");
	    }

	    # POP3_Version
	    elsif ($args[0] =~ /^pop3_version$/i) {
		($args[1] =~ $RE_printable) ? &setConfigParameter("POP3_Version", $args[1]) : &config_error("'$args[1]' is not a valid version string");
	    }

	    # POP3_Banner
	    elsif ($args[0] =~ /^pop3_banner$/i) {
		($args[1] =~ $RE_printable) ? &setConfigParameter("POP3_Banner", $args[1]) : &config_error("'$args[1]' is not a valid POP3 banner string");
	    }


	    # POP3_Hostname
	    elsif ($args[0] =~ /^pop3_hostname$/i) {
		($args[1] =~ $RE_validHostname) ? &setConfigParameter("POP3_Hostname", $args[1]) : &config_error("'$args[1]' is not a valid hostname");
	    }

	    # POP3_MBOXMaxMails
	    elsif ($args[0] =~ /^pop3_mbox_maxmails$/i) {
		($args[1] =~ /[\d]+/) ? &setConfigParameter("POP3_MBOXMaxMails", $args[1]) : &config_error("'$args[1]' is not an integer value");
	    }

	    # POP3_MBOXReRead
	    elsif ($args[0] =~ /^pop3_mbox_reread$/i) {
		($args[1] =~ /[\d]+/) ? &setConfigParameter("POP3_MBOXReRead", $args[1]) : &config_error("'$args[1]' is not an integer value");
	    }

	    # POP3_MBOXReBuild
	    elsif ($args[0] =~ /^pop3_mbox_rebuild$/i) {
		($args[1] =~ /[\d]+/) ? &setConfigParameter("POP3_MBOXReBuild", $args[1]) : &config_error("'$args[1]' is not an integer value");
	    }

	    # POP3_AuthReversibleOnly
	    elsif ($args[0] =~ /^pop3_auth_reversibleonly$/i) {
                if ($args[1] =~ /^yes$/i) {
                    &setConfigParameter("POP3_AuthReversibleOnly", 1);
                }
                elsif ($args[1] =~ /^no$/i) {
                    &setConfigParameter("POP3_AuthReversibleOnly", 0);
                }
                else {
                    &config_error("Invalid argument '$args[1]'");
                }
	    }

	    # POP3_EnableAPOP
	    elsif ($args[0] =~ /^pop3_enable_apop$/i) {
                if ($args[1] =~ /^yes$/i) {
                    &setConfigParameter("POP3_EnableAPOP", 1);
                }
                elsif ($args[1] =~ /^no$/i) {
                    &setConfigParameter("POP3_EnableAPOP", 0);
                }
                else {
                    &config_error("Invalid argument '$args[1]'");
                }
	    }

	    # POP3_EnableCapabilities
	    elsif ($args[0] =~ /^pop3_enable_capabilities$/i) {
		if ($args[1] =~ /^yes$/i) {
		    &setConfigParameter("POP3_EnableCapabilities", 1);
		}
		elsif ($args[1] =~ /^no$/i) {
		    &setConfigParameter("POP3_EnableCapabilities", 0);
		}
		else {
		    &config_error("Invalid argument '$args[1]'");
		}
	    }

	    # POP3_Capabilities
	    elsif ($args[0] =~ /^pop3_capability$/i) {
	        my $capability;
	        my $options;
	        # for details see: http://www.iana.org/assignments/pop3-extension-mechanism
	        if ($args[1] =~ /^(TOP|USER|SASL|RESP-CODES|LOGIN-DELAY|PIPELINING|EXPIRE|UIDL|IMPLEMENTATION|AUTH-RESP-CODE|STLS)$/i) {
	            $capability = uc($args[1]);
	            my $arg_num = 2;
	            while ($arg_num <= 10 && defined ($args[$arg_num]) && $args[$arg_num] ne "") {
	                last if ($args[$arg_num] =~ /^#/);
	                $options .= "$args[$arg_num] ";
	                $arg_num++;
	            }
	            $options =~ s/[\s\t]+$// if (defined ($options));
	            if (defined ($options) && $options =~ /^([\x20-\x7E]+)$/) {
	                $pop3_capabilities{$capability} = $options;
	            }
	            elsif (! defined ($options) || $options eq "") {
	                $pop3_capabilities{$capability} = "";
	            }
	            else {
	                &config_warn("Invalid option for POP3 capability '$capability'");
	            }
	        }
	        else {
                    &config_warn("'$args[1]' is not a valid POP3 capability");
    	        }
	    }

	    # POP3_KeyFileName
	    elsif ($args[0] =~ /^pop3_ssl_keyfile$/i) {
		if (! $args[1]) {
		    &config_error("missing argument for pop3_ssl_keyfile");
		}
		elsif ($args[1] !~ $RE_validFilename) {
		    &config_error("'$args[1]' is not a valid filename");
		}
		else {
		    &setConfigParameter("POP3_KeyFileName", $args[1]);
		}
	    }

	    # POP3_CrtFileName
	    elsif ($args[0] =~ /^pop3_ssl_certfile$/i) {
		if (! $args[1]) {
		    &config_error("missing argument for pop3_ssl_certfile");
		}
		elsif ($args[1] !~ $RE_validFilename) {
		    &config_error("'$args[1]' is not a valid filename");
		}
		else {
		    &setConfigParameter("POP3_CrtFileName", $args[1]);
		}
	    }

	    # POP3_DHFileName
	    elsif ($args[0] =~ /^pop3_ssl_dhfile$/i) {
		if (! $args[1]) {
		    &config_error("missing argument for pop3_ssl_dhfile");
		}
		elsif ($args[1] !~ $RE_validFilename) {
		    &config_error("'$args[1]' is not a valid filename");
		}
		else {
		    &setConfigParameter("POP3_DHFileName", $args[1]);
		}
	    }


	    #################################################
	    # POP3S
	    #################################################

	    # POP3S_BindPort
	    elsif ($args[0] =~ /^pop3s_bind_port$/i) {
		(($args[1] =~ /[\d]+/) && ($args[1] > 0) && ($args[1] < 65535)) ? &setConfigParameter("POP3S_BindPort", $args[1]) : &config_error("'$args[1]' is not a valid port number");
	    }

	    # POP3S_Version
	    elsif ($args[0] =~ /^pop3s_version$/i) {
		($args[1] =~ $RE_printable) ? &setConfigParameter("POP3S_Version", $args[1]) : &config_error("'$args[1]' is not a valid version string");
	    }

	    # POP3S_Banner
	    elsif ($args[0] =~ /^pop3s_banner$/i) {
		($args[1] =~ $RE_printable) ? &setConfigParameter("POP3S_Banner", $args[1]) : &config_error("'$args[1]' is not a valid POP3 banner string");
	    }


	    # POP3S_Hostname
	    elsif ($args[0] =~ /^pop3s_hostname$/i) {
		($args[1] =~ $RE_validHostname) ? &setConfigParameter("POP3S_Hostname", $args[1]) : &config_error("'$args[1]' is not a valid hostname");
	    }

	    # POP3S_MBOXMaxMails
	    elsif ($args[0] =~ /^pop3s_mbox_maxmails$/i) {
		($args[1] =~ /[\d]+/) ? &setConfigParameter("POP3S_MBOXMaxMails", $args[1]) : &config_error("'$args[1]' is not an integer value");
	    }

	    # POP3S_MBOXReRead
	    elsif ($args[0] =~ /^pop3s_mbox_reread$/i) {
		($args[1] =~ /[\d]+/) ? &setConfigParameter("POP3S_MBOXReRead", $args[1]) : &config_error("'$args[1]' is not an integer value");
	    }

	    # POP3S_MBOXReBuild
	    elsif ($args[0] =~ /^pop3s_mbox_rebuild$/i) {
		($args[1] =~ /[\d]+/) ? &setConfigParameter("POP3S_MBOXReBuild", $args[1]) : &config_error("'$args[1]' is not an integer value");
	    }

	    # POP3S_AuthReversibleOnly
	    elsif ($args[0] =~ /^pop3s_auth_reversibleonly$/i) {
                if ($args[1] =~ /^yes$/i) {
                    &setConfigParameter("POP3S_AuthReversibleOnly", 1);
                }
                elsif ($args[1] =~ /^no$/i) {
                    &setConfigParameter("POP3S_AuthReversibleOnly", 0);
                }
                else {
                    &config_error("Invalid argument '$args[1]'");
                }
	    }

	    # POP3S_EnableAPOP
	    elsif ($args[0] =~ /^pop3s_enable_apop$/i) {
                if ($args[1] =~ /^yes$/i) {
                    &setConfigParameter("POP3S_EnableAPOP", 1);
                }
                elsif ($args[1] =~ /^no$/i) {
                    &setConfigParameter("POP3S_EnableAPOP", 0);
                }
                else {
                    &config_error("Invalid argument '$args[1]'");
                }
	    }

	    # POP3S_EnableCapabilities
	    elsif ($args[0] =~ /^pop3s_enable_capabilities$/i) {
		if ($args[1] =~ /^yes$/i) {
		    &setConfigParameter("POP3S_EnableCapabilities", 1);
		}
		elsif ($args[1] =~ /^no$/i) {
		    &setConfigParameter("POP3S_EnableCapabilities", 0);
		}
		else {
		    &config_error("Invalid argument '$args[1]'");
		}
	    }

	    # POP3S_Capabilities
	    elsif ($args[0] =~ /^pop3s_capability$/i) {
	        my $capability;
	        my $options;
	        # for details see: http://www.iana.org/assignments/pop3-extension-mechanism
	        if ($args[1] =~ /^(TOP|USER|SASL|RESP-CODES|LOGIN-DELAY|PIPELINING|EXPIRE|UIDL|IMPLEMENTATION|AUTH-RESP-CODE|STLS)$/i) {
	            $capability = uc($args[1]);
	            my $arg_num = 2;
	            while ($arg_num <= 10 && defined ($args[$arg_num]) && $args[$arg_num] ne "") {
	                last if ($args[$arg_num] =~ /^#/);
	                $options .= "$args[$arg_num] ";
	                $arg_num++;
	            }
	            $options =~ s/[\s\t]+$// if (defined ($options));
	            if (defined ($options) && $options =~ /^([\x20-\x7E]+)$/) {
	                $pop3s_capabilities{$capability} = $options;
	            }
	            elsif (! defined ($options) || $options eq "") {
	                $pop3s_capabilities{$capability} = "";
	            }
	            else {
	                &config_warn("Invalid option for POP3S capability '$capability'");
	            }
	        }
	        else {
                    &config_warn("'$args[1]' is not a valid POP3S capability");
    	        }
	    }

	    # POP3S_KeyFileName
	    elsif ($args[0] =~ /^pop3s_ssl_keyfile$/i) {
		if (! $args[1]) {
		    &config_error("missing argument for pop3s_ssl_keyfile");
		}
		elsif ($args[1] !~ $RE_validFilename) {
		    &config_error("'$args[1]' is not a valid filename");
		}
		else {
		    &setConfigParameter("POP3S_KeyFileName", $args[1]);
		}
	    }

	    # POP3S_CrtFileName
	    elsif ($args[0] =~ /^pop3s_ssl_certfile$/i) {
		if (! $args[1]) {
		    &config_error("missing argument for pop3s_ssl_certfile");
		}
		elsif ($args[1] !~ $RE_validFilename) {
		    &config_error("'$args[1]' is not a valid filename");
		}
		else {
		    &setConfigParameter("POP3S_CrtFileName", $args[1]);
		}
	    }

	    # POP3S_DHFileName
	    elsif ($args[0] =~ /^pop3s_ssl_dhfile$/i) {
		if (! $args[1]) {
		    &config_error("missing argument for pop3s_ssl_dhfile");
		}
		elsif ($args[1] !~ $RE_validFilename) {
		    &config_error("'$args[1]' is not a valid filename");
		}
		else {
		    &setConfigParameter("POP3S_DHFileName", $args[1]);
		}
	    }


	    #################################################
	    # Quotd
	    #################################################

	    # Quotd_BindPort
	    elsif ($args[0] =~ /^quotd_bind_port$/i) {
		if (($args[1] =~ /[\d]+/) && ($args[1] > 0) && ($args[1] < 65535)) {
		    &setConfigParameter("Quotd_TCP_BindPort", $args[1]);
		    &setConfigParameter("Quotd_UDP_BindPort", $args[1]);
		}
		else {
		    &config_error("'$args[1]' is not a valid port number");
		}
	    }


	    #################################################
	    # SMTP
	    #################################################

	    # SMTP_BindPort
	    elsif ($args[0] =~ /^smtp_bind_port$/i) {
		(($args[1] =~ /[\d]+/) && ($args[1] > 0) && ($args[1] < 65535)) ? &setConfigParameter("SMTP_BindPort", $args[1]) : &config_error("'$args[1]' is not a valid port number");
	    }

	    # SMTP_FQDN_Hostname
	    elsif ($args[0] =~ /^smtp_fqdn_hostname$/i) {
		($args[1] =~ $RE_validFQDNHostname) ? &setConfigParameter("SMTP_FQDN_Hostname", $args[1]) : &config_error("'$args[1]' is not a valid FQDN hostname");
	    }


	    # SMTP_Banner
	    elsif ($args[0] =~ /^smtp_banner$/i) {
		($args[1] =~ $RE_printable) ? &setConfigParameter("SMTP_Banner", $args[1]) : &config_error("'$args[1]' is not a valid SMTP banner string");
	    }

	    # SMTP_HELO_required
	    elsif ($args[0] =~ /^smtp_helo_required$/i) {
		if ($args[1] =~ /^yes$/i) {
		    &setConfigParameter("SMTP_HELO_required", 1);
		}
		elsif ($args[1] =~ /^no$/i) {
		    &setConfigParameter("SMTP_HELO_required", 0);
		}
		else {
		    &config_error("Invalid argument '$args[1]'");
		}
	    }

	    # SMTP_Extended_SMTP
	    elsif ($args[0] =~ /^smtp_extended_smtp$/i) {
		if ($args[1] =~ /^yes$/i) {
		    &setConfigParameter("SMTP_Extended_SMTP", 1);
		}
		elsif ($args[1] =~ /^no$/i) {
		    &setConfigParameter("SMTP_Extended_SMTP", 0);
		}
		else {
		    &config_error("Invalid argument '$args[1]'");
		}
	    }

	    # SMTP_Service_Extensions
	    elsif ($args[0] =~ /^smtp_service_extension$/i) {
	        my $extension;
	        my $options;
	        # for details see: http://www.iana.org/assignments/mail-parameters
	        if ($args[1] =~ /^(SEND|SOML|SAML|VRFY|EXPN|HELP|TURN|8BITMIME|SIZE|VERB|ONEX|CHUNKING|BINARYMIME|CHECKPOINT|DELIVERBY|PIPELINING|DSN|ETRN|ENHANCEDSTATUSCODES|STARTTLS|NO-SOLICITING|MTRK|SUBMITTER|ATRN|AUTH|FUTURERELEASE|UTF8SMTP|VERP)$/i) {
	            $extension = uc($args[1]);
	            my $arg_num = 2;
	            while ($arg_num <= 10 && defined ($args[$arg_num]) && $args[$arg_num] ne "") {
	                last if ($args[$arg_num] =~ /^#/);
	                $options .= "$args[$arg_num] ";
	                $arg_num++;
	            }
	            $options =~ s/[\s\t]+$// if (defined ($options));
	            if (defined ($options) && $options =~ /^([\x20-\x7E]+)$/) {
	                $smtp_service_extensions{$extension} = $options;
	            }
	            elsif (! defined ($options) || $options eq "") {
	                $smtp_service_extensions{$extension} = "";
	            }
	            else {
	                &config_warn("Invalid option for SMTP extension '$extension'");
	            }
	        }
	        else {
                    &config_warn("'$args[1]' is not a valid SMTP extension");
    	        }
	    }

	    # SMTP_AuthReversibleOnly
	    elsif ($args[0] =~ /^smtp_auth_reversibleonly$/i) {
		if ($args[1] =~ /^yes$/i) {
		    &setConfigParameter("SMTP_AuthReversibleOnly", 1);
		}
		elsif ($args[1] =~ /^no$/i) {
		    &setConfigParameter("SMTP_AuthReversibleOnly", 0);
		}
		else {
		    &config_error("Invalid argument '$args[1]'");
		}
	    }

	    # SMTP_AuthRequired
	    elsif ($args[0] =~ /^smtp_auth_required$/i) {
		if ($args[1] =~ /^yes$/i) {
		    &setConfigParameter("SMTP_AuthRequired", 1);
		}
		elsif ($args[1] =~ /^no$/i) {
		    &setConfigParameter("SMTP_AuthRequired", 0);
		}
		else {
		    &config_error("Invalid argument '$args[1]'");
		}
	    }

	    # SMTP_KeyFileName
	    elsif ($args[0] =~ /^smtp_ssl_keyfile$/i) {
		if (! $args[1]) {
		    &config_error("missing argument for smtp_ssl_keyfile");
		}
		elsif ($args[1] !~ $RE_validFilename) {
		    &config_error("'$args[1]' is not a valid filename");
		}
		else {
		    &setConfigParameter("SMTP_KeyFileName", $args[1]);
		}
	    }

	    # SMTP_CrtFileName
	    elsif ($args[0] =~ /^smtp_ssl_certfile$/i) {
		if (! $args[1]) {
		    &config_error("missing argument for smtp_ssl_certfile");
		}
		elsif ($args[1] !~ $RE_validFilename) {
		    &config_error("'$args[1]' is not a valid filename");
		}
		else {
		    &setConfigParameter("SMTP_CrtFileName", $args[1]);
		}
	    }

	    # SMTP_DHFileName
	    elsif ($args[0] =~ /^smtp_ssl_dhfile$/i) {
		if (! $args[1]) {
		    &config_error("missing argument for smtp_ssl_dhfile");
		}
		elsif ($args[1] !~ $RE_validFilename) {
		    &config_error("'$args[1]' is not a valid filename");
		}
		else {
		    &setConfigParameter("SMTP_DHFileName", $args[1]);
		}
	    }


	    #################################################
	    # SMTPS
	    #################################################

	    # SMTPS_BindPort
	    elsif ($args[0] =~ /^smtps_bind_port$/i) {
		(($args[1] =~ /[\d]+/) && ($args[1] > 0) && ($args[1] < 65535)) ? &setConfigParameter("SMTPS_BindPort", $args[1]) : &config_error("'$args[1]' is not a valid port number");
	    }

	    # SMTPS_FQDN_Hostname
	    elsif ($args[0] =~ /^smtps_fqdn_hostname$/i) {
		($args[1] =~ $RE_validFQDNHostname) ? &setConfigParameter("SMTPS_FQDN_Hostname", $args[1]) : &config_error("'$args[1]' is not a valid FQDN hostname");
	    }


	    # SMTPS_Banner
	    elsif ($args[0] =~ /^smtps_banner$/i) {
		($args[1] =~ $RE_printable) ? &setConfigParameter("SMTPS_Banner", $args[1]) : &config_error("'$args[1]' is not a valid SMTP banner string");
	    }

	    # SMTPS_HELO_required
	    elsif ($args[0] =~ /^smtps_helo_required$/i) {
		if ($args[1] =~ /^yes$/i) {
		    &setConfigParameter("SMTPS_HELO_required", 1);
		}
		elsif ($args[1] =~ /^no$/i) {
		    &setConfigParameter("SMTPS_HELO_required", 0);
		}
		else {
		    &config_error("Invalid argument '$args[1]'");
		}
	    }

	    # SMTPS_Extended_SMTP
	    elsif ($args[0] =~ /^smtps_extended_smtp$/i) {
		if ($args[1] =~ /^yes$/i) {
		    &setConfigParameter("SMTPS_Extended_SMTP", 1);
		}
		elsif ($args[1] =~ /^no$/i) {
		    &setConfigParameter("SMTPS_Extended_SMTP", 0);
		}
		else {
		    &config_error("Invalid argument '$args[1]'");
		}
	    }

	    # SMTPS_Service_Extensions
	    elsif ($args[0] =~ /^smtps_service_extension$/i) {
	        my $extension;
	        my $options;
	        # for details see: http://www.iana.org/assignments/mail-parameters
	        if ($args[1] =~ /^(SEND|SOML|SAML|VRFY|EXPN|HELP|TURN|8BITMIME|SIZE|VERB|ONEX|CHUNKING|BINARYMIME|CHECKPOINT|DELIVERBY|PIPELINING|DSN|ETRN|ENHANCEDSTATUSCODES|STARTTLS|NO-SOLICITING|MTRK|SUBMITTER|ATRN|AUTH|FUTURERELEASE|UTF8SMTP|VERP)$/i) {
	            $extension = uc($args[1]);
	            my $arg_num = 2;
	            while ($arg_num <= 10 && defined ($args[$arg_num]) && $args[$arg_num] ne "") {
	                last if ($args[$arg_num] =~ /^#/);
	                $options .= "$args[$arg_num] ";
	                $arg_num++;
	            }
	            $options =~ s/[\s\t]+$// if (defined ($options));
	            if (defined ($options) && $options =~ /^([\x20-\x7E]+)$/) {
	                $smtps_service_extensions{$extension} = $options;
	            }
	            elsif (! defined ($options) || $options eq "") {
	                $smtps_service_extensions{$extension} = "";
	            }
	            else {
	                &config_warn("Invalid option for SMTP extension '$extension'");
	            }
	        }
	        else {
                    &config_warn("'$args[1]' is not a valid SMTP extension");
    	        }
	    }

	    # SMTPS_AuthReversibleOnly
	    elsif ($args[0] =~ /^smtps_auth_reversibleonly$/i) {
		if ($args[1] =~ /^yes$/i) {
		    &setConfigParameter("SMTPS_AuthReversibleOnly", 1);
		}
		elsif ($args[1] =~ /^no$/i) {
		    &setConfigParameter("SMTPS_AuthReversibleOnly", 0);
		}
		else {
		    &config_error("Invalid argument '$args[1]'");
		}
	    }

	    # SMTPS_AuthRequired
	    elsif ($args[0] =~ /^smtps_auth_required$/i) {
		if ($args[1] =~ /^yes$/i) {
		    &setConfigParameter("SMTPS_AuthRequired", 1);
		}
		elsif ($args[1] =~ /^no$/i) {
		    &setConfigParameter("SMTPS_AuthRequired", 0);
		}
		else {
		    &config_error("Invalid argument '$args[1]'");
		}
	    }

	    # SMTPS_KeyFileName
	    elsif ($args[0] =~ /^smtps_ssl_keyfile$/i) {
		if (! $args[1]) {
		    &config_error("missing argument for smtps_ssl_keyfile");
		}
		elsif ($args[1] !~ $RE_validFilename) {
		    &config_error("'$args[1]' is not a valid filename");
		}
		else {
		    &setConfigParameter("SMTPS_KeyFileName", $args[1]);
		}
	    }

	    # SMTPS_CrtFileName
	    elsif ($args[0] =~ /^smtps_ssl_certfile$/i) {
		if (! $args[1]) {
		    &config_error("missing argument for smtps_ssl_certfile");
		}
		elsif ($args[1] !~ $RE_validFilename) {
		    &config_error("'$args[1]' is not a valid filename");
		}
		else {
		    &setConfigParameter("SMTPS_CrtFileName", $args[1]);
		}
	    }

	    # SMTPS_DHFileName
	    elsif ($args[0] =~ /^smtps_ssl_dhfile$/i) {
		if (! $args[1]) {
		    &config_error("missing argument for smtps_ssl_dhfile");
		}
		elsif ($args[1] !~ $RE_validFilename) {
		    &config_error("'$args[1]' is not a valid filename");
		}
		else {
		    &setConfigParameter("SMTPS_DHFileName", $args[1]);
		}
	    }


	    #################################################
	    # TFTP
	    #################################################

	    # TFTP_BindPort
	    elsif ($args[0] =~ /^tftp_bind_port$/i) {
		(($args[1] =~ /[\d]+/) && ($args[1] > 0) && ($args[1] < 65535)) ? &setConfigParameter("TFTP_BindPort", $args[1]) : &config_error("'$args[1]' is not a valid port number");
	    }

	    # TFTP_AllowOverwrite
	    elsif ($args[0] =~ /^tftp_allow_overwrite$/i) {
		if ($args[1] =~ /^yes$/i) {
		    &setConfigParameter("TFTP_AllowOverwrite", 1);
		}
		elsif ($args[1] =~ /^no$/i) {
		    &setConfigParameter("TFTP_AllowOverwrite", 0);
		}
		else {
		    &config_error("Invalid argument '$args[1]'");
		}
	    }

	    # TFTP_EnableOptions
	    elsif ($args[0] =~ /^tftp_enable_options$/i) {
		if ($args[1] =~ /^yes$/i) {
		    &setConfigParameter("TFTP_EnableOptions", 1);
		}
		elsif ($args[1] =~ /^no$/i) {
		    &setConfigParameter("TFTP_EnableOptions", 0);
		}
		else {
		    &config_error("Invalid argument '$args[1]'");
		}
	    }

	    # TFTP_Options
	    elsif ($args[0] =~ /^tftp_option$/i) {
	        my $option;
	        my $values;
	        if ($args[1] =~ /^(blksize|timeout|tsize|multicast)$/i) {
	            $option = lc($args[1]);
	            my $arg_num = 2;
	            while ($arg_num <= 3 && defined ($args[$arg_num]) && $args[$arg_num] ne "") {
	                last if ($args[$arg_num] =~ /^#/);
	                $values .= "$args[$arg_num] ";
	                $arg_num++;
	            }
	            $values =~ s/[\s\t]+$// if (defined ($values));
	            if (defined ($values) && $values =~ /^([\x20-\x7E]+)$/) {
	                $tftp_options{$option} = $values;
	            }
	            elsif (! defined ($values) || $values eq "") {
	                $tftp_options{$option} = "";
	            }
	            else {
	                &config_warn("Invalid value for TFTP option '$option'");
	            }
	        }
	        else {
                    &config_warn("'$args[1]' is not a valid TFTP option");
    	        }
	    }


	    #################################################
	    # Time
	    #################################################

	    # Time_BindPort
	    elsif ($args[0] =~ /^time_bind_port$/i) {
		if (($args[1] =~ /[\d]+/) && ($args[1] > 0) && ($args[1] < 65535)) {
		    &setConfigParameter("Time_TCP_BindPort", $args[1]);
		    &setConfigParameter("Time_UDP_BindPort", $args[1]);
		}
		else {
		    &config_error("'$args[1]' is not a valid port number");
		}
	    }


	    #################################################
	    # Finger
	    #################################################

	    # Finger_BindPort
	    elsif ($args[0] =~ /^finger_bind_port$/i) {
		(($args[1] =~ /[\d]+/) && ($args[1] > 0) && ($args[1] < 65535)) ? &setConfigParameter("Finger_BindPort", $args[1]) : &config_error("'$args[1]' is not a valid port number");
	    }


	    #################################################
	    # Dummy
	    #################################################

	    # Dummy_BindPort
	    elsif ($args[0] =~ /^dummy_bind_port$/i) {
		if (($args[1] =~ /[\d]+/) && ($args[1] > 0) && ($args[1] < 65535)) {
		    &setConfigParameter("Dummy_TCP_BindPort", $args[1]);
		    &setConfigParameter("Dummy_UDP_BindPort", $args[1]);
		}
		else {
		    &config_error("'$args[1]' is not a valid port number");
		}
	    }

	    # Dummy_Banner
	    elsif ($args[0] =~ /^dummy_banner$/i) {
	        if (defined ($args[1]) && $args[1] =~ $RE_printable) {
	             &setConfigParameter("Dummy_Banner", $args[1]);
	        }
	        elsif (defined ($args[1]) && $args[1] =~ /^$/) {
	            &setConfigParameter("Dummy_Banner", "");
	        }
	        elsif (! defined ($args[1])) {
	            &config_error("'' is not a valid banner string");
	        }
	        else {
	            &config_error("'$args[1]' is not a valid banner string");
	        }
	    }

	    # Dummy_BannerWait
	    elsif ($args[0] =~ /^dummy_banner_wait$/i) {
                if ($args[1] =~ $RE_unsignedInt && int($args[1] >= 0) && int($args[1] < 601)) {
                    &setConfigParameter("Dummy_BannerWait", int($args[1]));
                }
                else {
                    &config_error("'$args[1]' is not an integer value of range [0..600]");
                }
            }


	    #################################################
	    # Redirect
	    #################################################

	    # Redirect_Enabled
	    elsif ($args[0] =~ /^redirect_enabled$/i) {
		if ($args[1] =~ /^yes$/i) {
		    &setConfigParameter("Redirect_Enabled", 1);
		}
		elsif ($args[1] =~ /^no$/i) {
		    &setConfigParameter("Redirect_Enabled", 0);
		}
		else {
		    &config_error("Invalid argument '$args[1]'");
		}
	    }

	    # Redirect_UnknownServices
	    elsif ($args[0] =~ /^redirect_unknown_services$/i) {
		if ($args[1] =~ /^yes$/i) {
		    &setConfigParameter("Redirect_UnknownServices", 1);
		}
		elsif ($args[1] =~ /^no$/i) {
		    &setConfigParameter("Redirect_UnknownServices", 0);
		}
		else {
		    &config_error("Invalid argument '$args[1]'");
		}
	    }

	    # Redirect_ExternalAddress
	    elsif ($args[0] =~ /^redirect_external_address$/i) {
		if ($args[1] =~ $RE_validIP) {
		    if ($args[1] =~ /^0.0.0.0$/) {
			&config_error("redirect_external_address '0.0.0.0' not allowed");
		    }
		    &setConfigParameter("Redirect_ExternalAddress", $args[1]);
		}
		else {
		    &config_error("'$args[1]' is not a valid IP address");
		}
	    }

	    # Redirect_ChangeTTL
	    elsif ($args[0] =~ /^redirect_change_ttl$/i) {
		if ($args[1] =~ /^yes$/i) {
		    &setConfigParameter("Redirect_ChangeTTL", 1);
		}
		elsif ($args[1] =~ /^no$/i) {
		    &setConfigParameter("Redirect_ChangeTTL", 0);
		}
		else {
		    &config_error("Invalid argument '$args[1]'");
		}
	    }

	    # Redirect_StaticRules
	    elsif ($args[0] =~ /^redirect_static_rule$/i) {
                my $re_ip_port = qr/^(([01]?[0-9][0-9]?|2[0-4][0-9]|25[0-5])\.){3}([01]?[0-9][0-9]?|2[0-4][0-9]|25[0-5]):([\d]{1,5})$/;
                my $re_ip_type = qr/^(([01]?[0-9][0-9]?|2[0-4][0-9]|25[0-5])\.){3}([01]?[0-9][0-9]?|2[0-4][0-9]|25[0-5]):(any|echo-reply|destination-unreachable|source-quench|redirect|echo-request|router-advertisement|router-solicitation|time-exceeded|parameter-problem|timestamp-request|timestamp-reply|address-mask-request|address-mask-reply)$/i;
                my $re_ip = qr/^(([01]?[0-9][0-9]?|2[0-4][0-9]|25[0-5])\.){3}([01]?[0-9][0-9]?|2[0-4][0-9]|25[0-5]):?$/;
                my $re_port = qr/^:([\d]{1,5})$/;
                my $re_type = qr/^:(any|echo-reply|destination-unreachable|source-quench|redirect|echo-request|router-advertisement|router-solicitation|time-exceeded|parameter-problem|timestamp-request|timestamp-reply|address-mask-request|address-mask-reply)$/i;

                if ($args[1] =~ /^(tc|ud)p$/i) {
                    if ($args[2] !~ $re_ip_port && $args[2] !~ $re_ip && $args[2] !~ $re_port) {
                        &config_error("'$args[2]' is not a valid $args[1] source ip:port value");
                    }
                    elsif ($args[3] !~ $re_ip_port && $args[3] !~ $re_ip && $args[3] !~ $re_port) {
                        &config_error("'$args[3]' is not a valid $args[1] destination ip:port value");
                    }
                    else {
                        my $key = lc($args[1]) . "," . $args[2];
                        $redirect_static_rules{$key} = $args[3];
                    }
                }
                elsif ($args[1] =~ /^icmp$/i) {
                    if ($args[2] !~ $re_ip_type && $args[2] !~ $re_ip && $args[2] !~ $re_type) {
                        &config_error("'$args[2]' is not a valid $args[1] source ip:type value");
                    }
                    elsif ($args[3] !~ $re_ip) {
                        &config_error("'$args[3]' is not a valid $args[1] destination ip value");
                    }
                    else {
                        my $key = lc($args[1]) . "," . $args[2];
                        $redirect_static_rules{$key} = $args[3];
                    }
                }
                else {
                    &config_error("'$args[1]' is not a valid protocol");
                }
	    }

	    # Redirect_ExcludePort
	    elsif ($args[0] =~ /^redirect_exclude_port$/i) {
		if ($args[1] =~ /^(tcp|udp):([\d]{1,5})$/i) {
		    my $proto = lc($1);
		    my $port = $2;
		    if (($port =~ /[\d]+/) && ($port > 0) && ($port < 65535)) {
		        push (@usedPorts, $args[1]);
		    }
		    else {
		        &config_error("'$port' is not a valid port number");
		    }
		}
		else {
		    &config_error("'$args[1]' is not a valid protocol:port value");
		}
	    }

	    # Redirect_IgnoreBootp
	    elsif ($args[0] =~ /^redirect_ignore_bootp$/i) {
		if ($args[1] =~ /^yes$/i) {
		    &setConfigParameter("Redirect_IgnoreBootp", 1);
		}
		elsif ($args[1] =~ /^no$/i) {
		    &setConfigParameter("Redirect_IgnoreBootp", 0);
		}
		else {
		    &config_error("Invalid argument '$args[1]'");
		}
	    }

	    # Redirect_IgnoreNetbios
	    elsif ($args[0] =~ /^redirect_ignore_netbios$/i) {
		if ($args[1] =~ /^yes$/i) {
		    &setConfigParameter("Redirect_IgnoreNetbios", 1);
		}
		elsif ($args[1] =~ /^no$/i) {
		    &setConfigParameter("Redirect_IgnoreNetbios", 0);
		}
		else {
		    &config_error("Invalid argument '$args[1]'");
		}
	    }

	    # Redirect_ICMP_Timestamp
	    elsif ($args[0] =~ /^redirect_icmp_timestamp$/i) {
		if ($args[1] =~ /^ms$/i) {
		    &setConfigParameter("Redirect_ICMP_Timestamp", 1);
		}
		elsif ($args[1] =~ /^sec$/i) {
		    &setConfigParameter("Redirect_ICMP_Timestamp", 2);
		}
		elsif ($args[1] =~ /^no$/i) {
		    &setConfigParameter("Redirect_ICMP_Timestamp", 0);
		}
		else {
		    &config_error("Invalid argument '$args[1]'");
		}
	    }


	    #################################################
	    # FTP
	    #################################################

	    # FTP_BindPort
	    elsif ($args[0] =~ /^ftp_bind_port$/i) {
		(($args[1] =~ /[\d]+/) && ($args[1] > 0) && ($args[1] < 65535)) ? &setConfigParameter("FTP_BindPort", $args[1]) : &config_error("'$args[1]' is not a valid port number");
	    }

	    # FTP_DataPort
	    elsif ($args[0] =~ /^ftp_data_port$/i) {
		(($args[1] =~ /[\d]+/) && ($args[1] > 0) && ($args[1] < 65535)) ? &setConfigParameter("FTP_DataPort", $args[1]) : &config_error("'$args[1]' is not a valid port number");
	    }

	    # FTP_Version
	    elsif ($args[0] =~ /^ftp_version$/i) {
		($args[1] =~ $RE_printable) ? &setConfigParameter("FTP_Version", $args[1]) : &config_error("'$args[1]' is not a valid version string");
	    }

	    # FTP_Banner
	    elsif ($args[0] =~ /^ftp_banner$/i) {
		($args[1] =~ $RE_printable) ? &setConfigParameter("FTP_Banner", $args[1]) : &config_error("'$args[1]' is not a valid FTP banner string");
	    }

	    # FTP_RecursiveDelete
	    elsif ($args[0] =~ /^ftp_recursive_delete$/i) {
		if ($args[1] =~ /^yes$/i) {
		    &setConfigParameter("FTP_RecursiveDelete", 1);
		}
		elsif ($args[1] =~ /^no$/i) {
		    &setConfigParameter("FTP_RecursiveDelete", 0);
		}
		else {
		    &config_error("Invalid argument '$args[1]'");
		}
	    }

	    # FTP_KeyFileName
	    elsif ($args[0] =~ /^ftp_ssl_keyfile$/i) {
		if (! $args[1]) {
		    &config_error("missing argument for ftp_ssl_keyfile");
		}
		elsif ($args[1] !~ $RE_validFilename) {
		    &config_error("'$args[1]' is not a valid filename");
		}
		else {
		    &setConfigParameter("FTP_KeyFileName", $args[1]);
		}
	    }

	    # FTP_CrtFileName
	    elsif ($args[0] =~ /^ftp_ssl_certfile$/i) {
		if (! $args[1]) {
		    &config_error("missing argument for ftp_ssl_certfile");
		}
		elsif ($args[1] !~ $RE_validFilename) {
		    &config_error("'$args[1]' is not a valid filename");
		}
		else {
		    &setConfigParameter("FTP_CrtFileName", $args[1]);
		}
	    }

	    # FTP_DHFileName
	    elsif ($args[0] =~ /^ftp_ssl_dhfile$/i) {
		if (! $args[1]) {
		    &config_error("missing argument for ftp_ssl_dhfile");
		}
		elsif ($args[1] !~ $RE_validFilename) {
		    &config_error("'$args[1]' is not a valid filename");
		}
		else {
		    &setConfigParameter("FTP_DHFileName", $args[1]);
		}
	    }


	    #################################################
	    # FTPS
	    #################################################

	    # FTPS_BindPort
	    elsif ($args[0] =~ /^ftps_bind_port$/i) {
		(($args[1] =~ /[\d]+/) && ($args[1] > 0) && ($args[1] < 65535)) ? &setConfigParameter("FTPS_BindPort", $args[1]) : &config_error("'$args[1]' is not a valid port number");
	    }

	    # FTPS_DataPort
	    elsif ($args[0] =~ /^ftps_data_port$/i) {
		(($args[1] =~ /[\d]+/) && ($args[1] > 0) && ($args[1] < 65535)) ? &setConfigParameter("FTPS_DataPort", $args[1]) : &config_error("'$args[1]' is not a valid port number");
	    }

	    # FTPS_Version
	    elsif ($args[0] =~ /^ftps_version$/i) {
		($args[1] =~ $RE_printable) ? &setConfigParameter("FTPS_Version", $args[1]) : &config_error("'$args[1]' is not a valid version string");
	    }

	    # FTPS_Banner
	    elsif ($args[0] =~ /^ftps_banner$/i) {
		($args[1] =~ $RE_printable) ? &setConfigParameter("FTPS_Banner", $args[1]) : &config_error("'$args[1]' is not a valid FTP banner string");
	    }

	    # FTPS_RecursiveDelete
	    elsif ($args[0] =~ /^ftps_recursive_delete$/i) {
		if ($args[1] =~ /^yes$/i) {
		    &setConfigParameter("FTPS_RecursiveDelete", 1);
		}
		elsif ($args[1] =~ /^no$/i) {
		    &setConfigParameter("FTPS_RecursiveDelete", 0);
		}
		else {
		    &config_error("Invalid argument '$args[1]'");
		}
	    }

	    # FTPS_KeyFileName
	    elsif ($args[0] =~ /^ftps_ssl_keyfile$/i) {
		if (! $args[1]) {
		    &config_error("missing argument for ftps_ssl_keyfile");
		}
		elsif ($args[1] !~ $RE_validFilename) {
		    &config_error("'$args[1]' is not a valid filename");
		}
		else {
		    &setConfigParameter("FTPS_KeyFileName", $args[1]);
		}
	    }

	    # FTPS_CrtFileName
	    elsif ($args[0] =~ /^ftps_ssl_certfile$/i) {
		if (! $args[1]) {
		    &config_error("missing argument for ftps_ssl_certfile");
		}
		elsif ($args[1] !~ $RE_validFilename) {
		    &config_error("'$args[1]' is not a valid filename");
		}
		else {
		    &setConfigParameter("FTPS_CrtFileName", $args[1]);
		}
	    }

	    # FTPS_DHFileName
	    elsif ($args[0] =~ /^ftps_ssl_dhfile$/i) {
		if (! $args[1]) {
		    &config_error("missing argument for ftps_ssl_dhfile");
		}
		elsif ($args[1] !~ $RE_validFilename) {
		    &config_error("'$args[1]' is not a valid filename");
		}
		else {
		    &setConfigParameter("FTPS_DHFileName", $args[1]);
		}
	    }


	    #################################################
	    # Syslog
	    #################################################

	    # Syslog_BindPort
	    elsif ($args[0] =~ /^syslog_bind_port$/i) {
		(($args[1] =~ /[\d]+/) && ($args[1] > 0) && ($args[1] < 65535)) ? &setConfigParameter("Syslog_BindPort", $args[1]) : &config_error("'$args[1]' is not a valid port number");
	    }

	    # Syslog_TrimMaxLength
	    elsif ($args[0] =~ /^syslog_trim_maxlength$/i) {
                if ($args[1] =~ /^yes$/i) {
                    &setConfigParameter("Syslog_TrimMaxLength", 1);
                }
                elsif ($args[1] =~ /^no$/i) {
                    &setConfigParameter("Syslog_TrimMaxLength", 0);
                }
                else {
                    &config_error("Invalid argument '$args[1]'");
                }
	    }

	    # Syslog_AcceptInvalid
	    elsif ($args[0] =~ /^syslog_accept_invalid$/i) {
                if ($args[1] =~ /^yes$/i) {
                    &setConfigParameter("Syslog_AcceptInvalid", 1);
                }
                elsif ($args[1] =~ /^no$/i) {
                    &setConfigParameter("Syslog_AcceptInvalid", 0);
                }
                else {
                    &config_error("Invalid argument '$args[1]'");
                }
	    }


	    #################################################
	    # IRC
	    #################################################

	    # IRC_BindPort
	    elsif ($args[0] =~ /^irc_bind_port$/i) {
		(($args[1] =~ /[\d]+/) && ($args[1] > 0) && ($args[1] < 65535)) ? &setConfigParameter("IRC_BindPort", $args[1]) : &config_error("'$args[1]' is not a valid port number");
	    }

	    # IRC_FQDN_Hostname
	    elsif ($args[0] =~ /^irc_fqdn_hostname$/i) {
		($args[1] =~ $RE_validFQDNHostname) ? &setConfigParameter("IRC_FQDN_Hostname", $args[1]) : &config_error("'$args[1]' is not a valid FQDN hostname");
	    }

	    # IRC_Version
	    elsif ($args[0] =~ /^irc_version$/i) {
		($args[1] =~ $RE_printable) ? &setConfigParameter("IRC_Version", $args[1]) : &config_error("'$args[1]' is not a valid version string");
	    }


	    #################################################
	    # IRCS
	    #################################################

	    # IRCS_BindPort
	    elsif ($args[0] =~ /^ircs_bind_port$/i) {
		(($args[1] =~ /[\d]+/) && ($args[1] > 0) && ($args[1] < 65535)) ? &setConfigParameter("IRCS_BindPort", $args[1]) : &config_error("'$args[1]' is not a valid port number");
	    }

	    # IRCS_FQDN_Hostname
	    elsif ($args[0] =~ /^ircs_fqdn_hostname$/i) {
		($args[1] =~ $RE_validFQDNHostname) ? &setConfigParameter("IRCS_FQDN_Hostname", $args[1]) : &config_error("'$args[1]' is not a valid FQDN hostname");
	    }

	    # IRCS_Version
	    elsif ($args[0] =~ /^ircs_version$/i) {
		($args[1] =~ $RE_printable) ? &setConfigParameter("IRCS_Version", $args[1]) : &config_error("'$args[1]' is not a valid version string");
	    }


	    #################################################
	    # Unknown keyword
	    else {
		&config_warn("Unknown keyword '$args[0]'");
	    }
	}
    }

    close(CONFIGFILE);

    # store static dns configuration
    &setConfigHash("DNS_StaticHostToIP", %dns_statichosttoip);
    &setConfigHash("DNS_StaticIPToHost", %dns_staticiptohost);
    # store http fakefile configuration
    &setConfigHash("HTTP_FakeFileExtToName", %http_fakefile_exttoname);
    &setConfigHash("HTTP_FakeFileExtToMIMEType", %http_fakefile_exttomimetype);
    &setConfigHash("HTTP_Static_FakeFilePathToName", %http_static_fakefile_pathtoname);
    &setConfigHash("HTTP_Static_FakeFilePathToMIMEType", %http_static_fakefile_pathtomimetype);
    # store https fakefile configuration
    &setConfigHash("HTTPS_FakeFileExtToName", %https_fakefile_exttoname);
    &setConfigHash("HTTPS_FakeFileExtToMIMEType", %https_fakefile_exttomimetype);
    &setConfigHash("HTTPS_Static_FakeFilePathToName", %https_static_fakefile_pathtoname);
    &setConfigHash("HTTPS_Static_FakeFilePathToMIMEType", %https_static_fakefile_pathtomimetype);
    # store static rules for redirect
    &setConfigHash("Redirect_StaticRules", %redirect_static_rules);
    # store smtp extensions
    &setConfigHash("SMTP_Service_Extensions", %smtp_service_extensions);
    # store smtps extensions
    &setConfigHash("SMTPS_Service_Extensions", %smtps_service_extensions);
    # store pop3 capabilities
    &setConfigHash("POP3_Capabilities", %pop3_capabilities);
    # store pop3s capabilities
    &setConfigHash("POP3S_Capabilities", %pop3s_capabilities);
    # store tftp options
    &setConfigHash("TFTP_Options", %tftp_options);

    &setConfigParameter("Chargen_TCP_ServiceName", "chargen_" . &getConfigParameter("Chargen_TCP_BindPort") . "_tcp");
    &setConfigParameter("Chargen_UDP_ServiceName", "chargen_" . &getConfigParameter("Chargen_UDP_BindPort") . "_udp");
    &setConfigParameter("Daytime_TCP_ServiceName", "daytime_" . &getConfigParameter("Daytime_TCP_BindPort") . "_tcp");
    &setConfigParameter("Daytime_UDP_ServiceName", "daytime_" . &getConfigParameter("Daytime_UDP_BindPort") . "_udp");
    &setConfigParameter("Discard_TCP_ServiceName", "discard_" . &getConfigParameter("Discard_TCP_BindPort") . "_tcp");
    &setConfigParameter("Discard_UDP_ServiceName", "discard_" . &getConfigParameter("Discard_UDP_BindPort") . "_udp");
    &setConfigParameter("DNS_ServiceName", "dns_" . &getConfigParameter("DNS_BindPort") . "_tcp_udp");
    &setConfigParameter("Echo_TCP_ServiceName", "echo_" . &getConfigParameter("Echo_TCP_BindPort") . "_tcp");
    &setConfigParameter("Echo_UDP_ServiceName", "echo_" . &getConfigParameter("Echo_UDP_BindPort") . "_udp");
    &setConfigParameter("HTTP_ServiceName", "http_" . &getConfigParameter("HTTP_BindPort") . "_tcp");
    &setConfigParameter("HTTPS_ServiceName", "https_" . &getConfigParameter("HTTPS_BindPort") . "_tcp");
    &setConfigParameter("Ident_ServiceName", "ident_" . &getConfigParameter("Ident_BindPort") . "_tcp");
    &setConfigParameter("NTP_ServiceName", "ntp_" . &getConfigParameter("NTP_BindPort") . "_udp");
    &setConfigParameter("POP3_ServiceName", "pop3_" . &getConfigParameter("POP3_BindPort") . "_tcp");
    &setConfigParameter("POP3S_ServiceName", "pop3s_" . &getConfigParameter("POP3S_BindPort") . "_tcp");
    &setConfigParameter("Quotd_TCP_ServiceName", "quotd_" . &getConfigParameter("Quotd_TCP_BindPort") . "_tcp");
    &setConfigParameter("Quotd_UDP_ServiceName", "quotd_" . &getConfigParameter("Quotd_UDP_BindPort") . "_udp");
    &setConfigParameter("SMTP_ServiceName", "smtp_" . &getConfigParameter("SMTP_BindPort") . "_tcp");
    &setConfigParameter("SMTPS_ServiceName", "smtps_" . &getConfigParameter("SMTPS_BindPort") . "_tcp");
    &setConfigParameter("Time_TCP_ServiceName", "time_" . &getConfigParameter("Time_TCP_BindPort") . "_tcp");
    &setConfigParameter("Time_UDP_ServiceName", "time_" . &getConfigParameter("Time_UDP_BindPort") . "_udp");
    &setConfigParameter("TFTP_ServiceName", "tftp_" . &getConfigParameter("TFTP_BindPort") . "_udp");
    &setConfigParameter("Finger_ServiceName", "finger_" . &getConfigParameter("Finger_BindPort") . "_tcp");
    &setConfigParameter("Dummy_TCP_ServiceName", "dummy_" . &getConfigParameter("Dummy_TCP_BindPort") . "_tcp");
    &setConfigParameter("Dummy_UDP_ServiceName", "dummy_" . &getConfigParameter("Dummy_UDP_BindPort") . "_udp");
    &setConfigParameter("FTP_ServiceName", "ftp_" . &getConfigParameter("FTP_BindPort") . "_tcp");
    &setConfigParameter("FTPS_ServiceName", "ftps_" . &getConfigParameter("FTPS_BindPort") . "_tcp");
    &setConfigParameter("Syslog_ServiceName", "syslog_" . &getConfigParameter("Syslog_BindPort") . "_udp");
    &setConfigParameter("IRC_ServiceName", "irc_" . &getConfigParameter("IRC_BindPort") . "_tcp");
    &setConfigParameter("IRCS_ServiceName", "ircs_" . &getConfigParameter("IRCS_BindPort") . "_tcp");

    # check command line options
    if (my $session = &INetSim::CommandLine::getCommandLineOption("session")) {
	&setConfigParameter("SessionID", $session);
    }

    if (my $faketime_initdelta = &INetSim::CommandLine::getCommandLineOption("faketime_initdelta")) {
	&setConfigParameter("Faketime_Delta", int($faketime_initdelta));
    }

    if (my $faketime_autodelay = &INetSim::CommandLine::getCommandLineOption("faketime_autodelay")) {
	&setConfigParameter("Faketime_AutoDelay", int($faketime_autodelay));
    }

    if (my $faketime_autoincr = &INetSim::CommandLine::getCommandLineOption("faketime_autoincr")) {
	&setConfigParameter("Faketime_AutoIncrement", int($faketime_autoincr));
    }

    if (my $default_max_childs = &INetSim::CommandLine::getCommandLineOption("max_childs")) {
	&setConfigParameter("Default_MaxChilds", int($default_max_childs));
    }

    if (my $bind_address = &INetSim::CommandLine::getCommandLineOption("bind_address")) {
	&setConfigParameter("Default_BindAddress", $bind_address);
    }

    if (my $user = &INetSim::CommandLine::getCommandLineOption("user")) {
	&setConfigParameter("Default_RunAsUser", $user);
    }

    &INetSim::Log::MainLog("Configuration file parsed successfully.");
}


sub splitline {
    # split up a line into words
    # multiple words in quotes count as one word
    # return an array containing the words
    my $line = shift;
    my $i;
    my $char = "";
    my $word = "";
    my $in_word = 0;
    my $in_quotes = 0;
    my @words = (); 

    for ($i=0; $i<length($line);$i++) {
	$char = substr($line, $i, 1);
	if ($char =~ /\s/) {
	    if ($in_quotes) {
		$word .= $char;
	    }
	    elsif ($in_word) {
		$in_word = 0;
		push (@words, $word);
		$word = "";
	    }
	    else {
		next;
	    }
	}
	elsif ($char =~ /\"/) {
	    if (!$in_quotes) {
		$in_quotes = 1;
	    }
	    else {
		$in_quotes = 0;
		push (@words, $word);
		$in_word = 0;
		$word = "";
	    }
	}
	else {
	    $word .= $char;
	    $in_word = 1;
	}
    }
    if ($in_quotes) {
	&config_error ("Missing quote sign");
    }
    elsif ($word ne "") {
	push (@words, $word);
    }

    return @words;
}


sub config_warn {
    my $msg = shift;

    &INetSim::Log::MainLog("Warning: " . $msg . " at line $lineNumber");
}


sub config_error {
    my $msg = shift;

    &INetSim::error_exit("$msg in configuration file '" . &INetSim::Config::getConfigParameter("ConfigFileName") . "' at line $lineNumber");
}


sub getConfigParameter {
    my $key = shift;

    if (! defined $key) {
	# programming error -> exit
	&INetSim::error_exit("getConfigParameter() called without parameter");
    }
    elsif (exists $ConfigOptions{$key}) {
#        if (UNIVERSAL::isa ($ConfigOptions{$key}, "ARRAY")) {
#	    # we have an array
#            return @{$ConfigOptions{$key}};
#        }
#        elsif (UNIVERSAL::isa ($ConfigOptions{$key}, "HASH")) {
#	    # we have a hash
#            return %{$ConfigOptions{$key}};
#        }
#        else {
#	    # we have a scalar
            return $ConfigOptions{$key};
#        }
    }
    else {
	# programming error -> exit
	&INetSim::error_exit("No such configuration parameter '$key'");
    }
}


sub getConfigHash {
    my $key = shift;

    if (! defined $key) {
	# programming error -> exit
	&INetSim::error_exit("getConfigHash() called without parameter.");
    }
    elsif (exists $ConfigOptions{$key}) {
            return %{$ConfigOptions{$key}};
    }
    else {
	# programming error -> exit
	&INetSim::error_exit("No such configuration parameter '$key'.");
    }
}


sub setConfigHash {
    my ($key, %values) = @_;

    if (! defined $key) {
	# programming error -> exit
	&INetSim::error_exit("setConfigHash() called without key parameter.");
    }
#    elsif (! %values) {
#	# programming error -> exit
#	&INetSim::error_exit("setConfigHash() called without values.");
#    }
    elsif (exists $ConfigOptions{$key}) {
	%{$ConfigOptions{$key}} = %values;
    }
    else {
	# programming error -> exit
	&INetSim::error_exit("No such configuration option '$key'.");
    }
}


sub setConfigParameter {
    my $key = shift;
    my $value = shift;

    if (! defined $key) {
	# programming error -> exit
	&INetSim::error_exit("setConfigParameter() called without key parameter.");
    }
    elsif (! defined $value) {
	# programming error -> exit
	&INetSim::error_exit("setConfigParameter() called without value.");
    }
    elsif (exists $ConfigOptions{$key}) {
	$ConfigOptions{$key} = $value;
    }
    else {
	# programming error -> exit
	&INetSim::error_exit("No such configuration option '$key'.");
    }
}


sub getServicesToStart {
    return @ServicesToStart;
}


sub getUsedPorts {
    my %seen = ();

    foreach my $key (keys %ConfigOptions) {
        if (defined ($key) && $key && $key) {
            if ($key =~ /TCP_BindPort$/ || $key =~ /(DNS|HTTP|Ident|POP3|SMTP|Finger|FTP|IRC)_BindPort$/ || ($SSL && $key =~ /(HTTPS|POP3S|SMTPS|FTPS|IRCS)_BindPort$/)) {
                push (@usedPorts, "tcp:$ConfigOptions{$key}");
            }
            if ($key =~ /UDP_BindPort$/ || $key =~ /(DNS|NTP|TFTP|Syslog)_BindPort$/) {
                push (@usedPorts, "udp:$ConfigOptions{$key}");
            }
# for future use !
#            if ($key =~ /(FTP|FTPS|IRC)_DataPort$/) {
#                push (@usedPorts, "tcp:$ConfigOptions{$key}");
#            }
        }
    }
    return (grep { ! $seen{ $_ }++ } @usedPorts);
}


1;
#############################################################
#
# History:
#
# Version 0.105 (2013-11-02) th
# - set config parameter HTTP(S)_POSTDataDir correctly
#   if '--data-dir' command line option is used
#
# Version 0.104 (2012-10-01) th
# - changed ServiceName format
#
# Version 0.103 (2010-11-03) th
# - changed regexp check with http(s)_static_fakefile
#
# Version 0.102 (2010-09-18) th
# - added support for HTTP(S) static fakefiles
#
# Version 0.101 (2010-04-19) me
# - added configuration variables 'IRC[S]_FQDN_Hostname' and 'IRC[S]_Version'
# - added configuration options 'irc[s]_fqdn_hostname' and 'irc[s]_version'
#
# Version 0.100 (2010-04-15) me
# - added better checks for SSL support
# - added warning for enabled SSL services without SSL support
#
# Version 0.99  (2010-04-11) th
# - changed possible value for 'Redirect_ICMP_Timestamp'
#   from empty string to 'no'
#
# Version 0.98  (2010-04-02) me
# - added new variable 'Redirect_ICMP_Timestamp'
#
# Version 0.97  (2010-02-19) me
# - added support for icmp redirects
#
# Version 0.96  (2009-12-20) th
# - changed default filenames for SSL certificate and keyfile
#
# Version 0.95  (2009-12-19) me
# - added variables 'CertDir', 'Default_KeyFileName', 'Default_CrtFileName'
#   and 'Default_DHFileName'
# - changed path to certificate locations
#
# Version 0.94  (2009-12-18) th
# - added path to certificate locations for config options
#
# Version 0.93  (2009-12-15) th
# - changed default SSL certificate locations
#
# Version 0.92  (2009-10-12) me
# - removed 'TFTP_UploadData', 'TFTP_UploadIndex' and 'TFTP_EnableUpload'
# - added new variables 'TFTP_UploadDir', 'TFTP_AllowOverwrite'
#   and 'TFTP_EnableOptions'
# - added configuration hash 'TFTP_Options'
#
# Version 0.91  (2009-10-06) me
# - added configuration options '*_ssl_dhfile' and variables
#   '*_DHFileName' for optional Diffie-Hellman parameter files
# - added configuration options 'smtp[s]_auth_required' and
#   variables 'SMTP[S]_AuthRequired'
#
# Version 0.90  (2009-10-04) me
# - bugfix: changed *ssl_crtfile to *ssl_certfile
#
# Version 0.89  (2009-10-02) me
# - added configuration options for IRC[s]
#
# Version 0.88  (2009-09-25) me
# - added variables 'FTP[S]_Version', 'POP3[S]_Version'
#
# Version 0.87  (2009-09-24) me
# - added variable 'DNS_Version'
#
# Version 0.86  (2009-09-23) me
# - added service IRC
#
# Version 0.85  (2009-09-07) me
# - added variables 'POP3[S]_EnableAPOP', 'POP3[S]_EnableCapabilities'
# - added configuration hashes 'POP3[s]_Capabilities'
#
# Version 0.84  (2009-09-05) me
# - added cert file options for HTTP (RFC 2817)
# - disabled 'Debug' flag
#
# Version 0.83  (2009-09-04) me
# - changed default path for smtps cert files
# - added variable 'FTP_DataPort'
# - services POP3, HTTP and FTP prepared for using SSL
#
# Version 0.82  (2009-09-03) me
# - added GenericServer configuration options for SMTPS
#
# Version 0.81  (2009-09-02) me
# - added variables 'SMTP_KeyFileName' and 'SMTP_CrtFileName'
#
# Version 0.80  (2008-09-26) me
# - changed default timeout for services to 120 seconds
# - bugfix: stop parameter parsing for smtp extensions after '#'
# - added variables 'Dummy_Banner' and 'Dummy_BannerWait'
# - bugfix: added setConfigParameter for ftp path variables
#
# Version 0.79  (2008-09-21) me
# - added variable 'SMTP_Extended_SMTP' as SMTP/ESMTP switch
# - added configuration hash 'SMTP_Service_Extensions' for ESMTP
#   extensions to use
# - removed SMTP 'Enhanced-Status-Codes' stuff, because it can
#   now be configured via 'SMTP_Service_Extensions' hash
#
# Version 0.78  (2008-09-20) me
# - added variable 'SMTP_EnhancedStatusCodes' and configuration
#   option 'smtp_enhanced_statuscodes'
# - added variable 'FTP_RecursiveDelete' and configuration option
#   'ftp_recursive_delete'
# - added service syslog to function getUsedPorts()
#
# Version 0.77  (2008-09-08) me
# - added service syslog
#
# Version 0.76  (2008-08-28) me
# - added configuration variable 'FTP_UploadDir'
#
# Version 0.75  (2008-08-27) me
# - added configuration variables 'Redirect_IgnoreBootp' and
#   'Redirect_IgnoreNetbios'
# - added configuration variable 'FTP_DocumentRoot'
#
# Version 0.74  (2008-08-27) me
# - moved check for '0.0.0.0' in bind_address to redirect module
#
# Version 0.73  (2008-08-24) me
# - added GenericServer configuration options for FTP
# - added service FTP to function getUsedPorts()
# - added variable 'ReportLanguage' and configuration option 'report_language'
#
# Version 0.72  (2008-08-20) me
# - added service FTP
#
# Version 0.71  (2008-08-09) th
# - added 'Create_Reports'
#
# Version 0.70  (2008-08-02) th
# - added HTTP_POSTDataDir
#
# Version 0.69  (2008-07-06) th
# - changed default for 'Redirect_Enabled' to '0'
#
# Version 0.68  (2008-06-26) th
# - Bugfix: full string match on configuration options
# - renamed configuration option 'default_timeout' to 'service_timeout'
# - renamed configuration option 'default_max_childs' to 'service_max_childs'
# - renamed configuration option 'default_run_as_user' to 'service_run_as_user'
# - renamed configuration option 'bind_address' to 'service_bind_address'
#
# Version 0.67  (2008-06-24) me
# - added configuration option 'redirect_exclude_port'
#
# Version 0.66  (2008-06-15) me
# - changed Default_MaxChilds value to 10
#
# Version 0.65  (2008-06-13) th
# - removed bind_address configuration options for
#   individual services
# - renamed default_bind_adress to bind_address
# - disallow '0.0.0.0' for bind_address, ntp_server_ip and
#   redirect_external_address
#
# Version 0.64  (2008-03-25) me
# - changed protocol for NTP_ServiceName to udp
#
# Version 0.63  (2008-03-19) me
# - added configuration option Default_TimeOut
#
# Version 0.62  (2008-03-17) me
# - fixed some typos
#
# Version 0.61  (2008-03-17) me
# - added configuration option Redirect_Enabled
# - bugfix: disabled check for empty hash in function setConfigHash()
#
# Version 0.60  (2008-03-16) me
# - added function getUsedPorts()
# - added configuration variables Redirect_UnknownServices,
#   Redirect_ExternalAddress, Redirect_ChangeTTL and
#   Redirect_StaticRules for 'Redirect' module
#
# Version 0.59  (2008-03-15) me
# - added configuration variable NTP_StrictChecks
#
# Version 0.58  (2008-03-06) me
# - added GenericServer configuration options for "Dummy" TCP/UDP
#
# Version 0.57  (2007-12-09) me
# - added configuration variable POP3_AuthReversibleOnly
# - added configuration variable SMTP_AuthReversibleOnly
#
# Version 0.56  (2007-11-07) me
# - added GenericServer configuration options for Finger
#
# Version 0.55  (2007-10-21) th
# - bugfix: also use default SubLogfileName "service.log"
#   instead of "sub.log" if commandline option "log_dir" is used
# - bugfix: POP3_MBOXDirName was not set if commandline option
#   "data_dir" used
# - removed unused configuration variable POP3_MBOXFileName
# - changed POP3_MBOXDirName from "pop3/" to "pop3"
# - changed default POP3_MBOXMaxMails to 10
#
# Version 0.54  (2007-10-20) me
# - added configuration variable POP3_MBOXMaxMails
# - added configuration variable POP3_MBOXReRead
# - added configuration variable POP3_MBOXReBuild
#
# Version 0.53  (2007-10-12) th
# - changed default SubLogfileName to "service.log"
#
# Version 0.52  (2007-05-24) th
# - renamed HTTP_Default_FakeFileType to HTTP_Default_FakeFileMIMEType
# - now MIME type must be specified instead of file extension for
#   default fake file
# - renamed HTTP_FakeFiles to HTTP_FakeFileExtToMIMEType
# - new variable HTTP_FakeFileExtToMIMEType
# - now MIME type must be specified for every fake file
# - added variable TFTP_EnableUpload
#
# Version 0.51  (2007-05-18) th
# - changed $basedir to $currentdir
# - add full path to ConfigFileName
#
# Version 0.50  (2007-05-16) th
# - added missing setConfigParameter for DebugLogfileName
#   when log-dir specified on command line
# - added configuration variables LogDir and DataDir
# - added logging of LogDir, DataDir, ReportDir and
#   ConfigFileName
#
# Version 0.49  (2007-05-15) th
# - check if users specified to run services exist on system
# - added configuration variables DNS_RunAsUser, DNS_RunAsGroup
#   and DNS_MaxChilds
#
# Version 0.48  (2007-05-14) th
# - changed DNS default IP to 127.0.0.1
#
# Version 0.47  (2007-05-02) th
# - merged versions 0.45b and 0.46
# - added configuration variables "Debug" and "DebugLogfileName"
#
# Version 0.46  (2007-04-30) th
# - set Default_RunAsGroup to 'inetsim' and removed
#   configuration file parsing for this option
# - after parsing configuration file, check command line options
#   with getCommandLineOption()
# - added function getServicesToStart()
#
# Version 0.45b (2007-04-28) me
# - added configuration variable POP3_MBOXDirName
# - changed default value for POP3_MBOXFileName to pop3.mbx
#
# Version 0.45  (2007-04-29) th
# - moved command line parser to CommandLine.pm
#
# Version 0.44  (2007-04-27) th
# - added functions getConfigHash and setConfigHash
# - moved global configuration variables for DNS, HTTP to shared hash
# - added configuration variable ReportDir
# - moved global configuration variables for SessionID,
#   ConfigFileName, MainLogfileName, SubLogfileName to shared hash
#
# Version 0.43  (2007-04-26) th
# - moved global configuration variables for Chargen, Discard,
#   Echo, Ident, NTP, POP3, Quotd, SMTP, TFTP, Time to shared hash
#
# Version 0.42  (2007-04-25) th
# - added shared hash for config parameters
# - added functions getConfigParameter and setConfigParameter
# - moved global configuration variables for FakeTime and DayTime
#   to shared hash
#
# Version 0.41  (2007-04-25) me
# - fixed a typo with commandline option delay
#
# Version 0.40  (2007-04-24) me
# - removed basedir option
# - added log-dir option
# - added data-dir option
# - added delta option
# - added configuration option $INetSim::Config::LogDir
# - added configuration option $INetSim::Config::DataDir
#
# Version 0.39  (2007-04-22) th
# - use INetSim::error_exit() instead of die() and exit()
# - changed some error messages
# - set default $INetSim::Config::BaseDir to cwd() instead of "."
#
# Version 0.38  (2007-04-21) me
# - merged th's and me's current version
# - changed handling of basedir option
# - changed handling of session option
#
# Version 0.37  (2007-04-21) th
# - changed handling of HTTP default fakefile
# - added configuration option $INetSim::Config::HTTP_Default_FakeFileType
# - added configuration option $INetSim::Config::HTTP_Default_FakeFileName
#
# Version 0.36  (2007-04-20) me
# - added configuration option $INetSim::Config::SessionID
# - added parsing of 'session' ($INetSim::Config::SessionID)
#
# Version 0.35  (2007-04-19) me
# - added parsing of commandline options
# - added reg-ex for unsigned integer
#
# Version 0.34  (2007-04-09) th
# - renamed INetSim::Config::FakeTimeDelta
#        to INetSim::Config::FakeTimeInitDelta
# - added configuration options
#   INetSim::Config::FakeTimeAutoDelay
#   INetSim::Config::FakeTimeAutoIncrement
#
# Version 0.33  (2007-04-06) th
# - added parsing of BindAddress and BindPort for all services
#
# Version 0.32  (2007-04-05) th
# - changed default values for MaxChilds, BindAddress,
#   RunAsUser and RunAsGroup to 'undef' for all services
# - added parsing of default_max_childs, default_bind_address,
#   default_run_as_user and default_run_as_group
# - generate service names with configured bind port
#
# Version 0.31  (2007-04-02) th
# - added configuration options INetSim::Config::DNS_StaticHostToIP
#   and INetSim::Config::DNS_StaticIPToHost
#
# Version 0.30  (2007-04-01) th
# - merged me's and th's current version
#
# Version 0.29  (2007-03-30) me
# - added GenericServer configuration options for TFTP
#
# Version 0.28  (2007-03-29) th
# - fixed bug if a configuration parameter is '0'
# - added configuration option $INetSim::Config::HTTP_FakeMode
# - added configuration option $INetSim::Config::HTTP_FakeFileDir
# - added configuration option %INetSim::Config::HTTP_FakeFiles
#
# Version 0.27  (2007-03-28) th
# - added configuration option $INetSim::Config::HTTP_Version
# - added configuration option $INetSim::Config::HTTP_MIMETypesFile
#
# Version 0.26  (2007-03-27) th
# - added configuration option $INetSim::Config::Quotd_QuotesFileName
#
# Version 0.25  (2007-03-26) th
# - added GenericServer configuration options for SMTP
# - added GenericServer configuration options for POP3
# - added configuration option $INetSim::Config::SMTP_HELO_required
# - added configuration option $INetSim::Config::SMTP_MBOXFileName
# - added configuration option $INetSim::Config::POP3_MBOXFileName
# - added GenericServer configuration options for Daytime TCP/UDP
# - added GenericServer configuration options for Time TCP/UDP
# - added GenericServer configuration options for Quotd TCP/UDP
# - added GenericServer configuration options for Discard TCP/UDP
# - added GenericServer configuration options for NTP
# - added GenericServer configuration options for Ident
#
# Version 0.24  (2007-03-24) th
# - added GenericServer configuration options for Chargen TCP/UDP
# - added GenericServer configuration options for HTTP
#
# Version 0.23  (2007-03-20) th
# - added GenericServer configuration options for Echo TCP/UDP
#
# Version 0.22  (2007-03-18) th
# - added min/max checks for fake time delta
# - added configuration options
#   INetSim::Config::SMTP_FQDN_Hostname
#   INetSim::Config::SMTP_Banner
#   INetSim::Config::NTP_Server_IP
#
# Version 0.21  (2007-03-17) th
# - added configuration options
#   INetSim::Config::DNS_Default_IP
#   INetSim::Config::DNS_Default_Hostname
#   INetSim::Config::DNS_Default_Domainname
#
# Version 0.2   (2007-03-16) th
# - added configuration options
#   INetSim::Config::ServicesToStart
#   INetSim::Config::FakeTimeDelta
#
#############################################################
