# -*- perl -*-
#
# INetSim - An internet simulation framework
#
# (c)2007-2014 Matthias Eckert, Thomas Hungenberg
#
# Version 1.2.5 (2014-05-24)
#
# For history/changelog see bottom of this file.
#
#############################################################

package INetSim;

use strict;
use warnings;
use POSIX;
# modules to use
use INetSim::CommandLine;
use INetSim::Config;
use INetSim::Log;
use INetSim::FakeTime;
use INetSim::Chargen::TCP;
use INetSim::Chargen::UDP;
use INetSim::Daytime::TCP;
use INetSim::Daytime::UDP;
use INetSim::Discard::TCP;
use INetSim::Discard::UDP;
use INetSim::Echo::TCP;
use INetSim::Echo::UDP;
use INetSim::Quotd::TCP;
use INetSim::Quotd::UDP;
use INetSim::Time::TCP;
use INetSim::Time::UDP;
use INetSim::HTTP;
use INetSim::Ident;
use INetSim::NTP;
use INetSim::SMTP;
use INetSim::POP3;
use INetSim::DNS;
use INetSim::TFTP;
use INetSim::Report;
use INetSim::Finger;
use INetSim::Dummy::TCP;
use INetSim::Dummy::UDP;
use INetSim::FTP;
use INetSim::Syslog;
use INetSim::IRC;

my $VERSION = "INetSim 1.2.5 (2014-05-24)";


#############################################################
# Local variables

my $PPID = $$;   # Parent PID
my @childs = (); # Child PIDs


#############################################################
# Child process handling
#
sub fork_services {
    my @services_to_start = &INetSim::Config::getServicesToStart();
    foreach (@services_to_start) {
	my $pid = fork();
	if ($pid) {
	    # we are the parent process
	    push(@childs, $pid);
	}
	elsif ($pid == 0){
	    # we are the child process
	    if(/^dns$/) {
		&INetSim::DNS::dns;
	    }
	    elsif(/^smtp$/) {
		INetSim::SMTP->run;
	    }
	    elsif(/^smtps$/) {
		INetSim::SMTP->new({ SSL => 1 })->run;
	    }
	    elsif(/^pop3$/) {
		INetSim::POP3->run;
	    }
	    elsif(/^pop3s$/) {
		INetSim::POP3->new({ SSL => 1 })->run;
	    }
	    elsif(/^http$/) {
		INetSim::HTTP->run;
	    }
	    elsif(/^https$/) {
		INetSim::HTTP->new({ SSL => 1 })->run;
	    }
	    elsif(/^ntp$/) {
		INetSim::NTP->run;
	    }
	    elsif(/^time_tcp$/) {
		INetSim::Time::TCP->run;
	    }
	    elsif(/^time_udp$/) {
		INetSim::Time::UDP->run;
	    }
	    elsif(/^daytime_tcp$/) {
		INetSim::Daytime::TCP->run;
	    }
	    elsif(/^daytime_udp$/) {
		INetSim::Daytime::UDP->run;
	    }
	    elsif(/^ident$/) {
		INetSim::Ident->run;
	    }
	    elsif(/^echo_tcp$/) {
		INetSim::Echo::TCP->run;
	    }
	    elsif(/^echo_udp$/) {
		INetSim::Echo::UDP->run;
	    }
	    elsif(/^discard_tcp$/) {
		INetSim::Discard::TCP->run;
	    }
	    elsif(/^discard_udp$/) {
		INetSim::Discard::UDP->run;
	    }
	    elsif(/^chargen_tcp$/) {
		INetSim::Chargen::TCP->run;
	    }
	    elsif(/^chargen_udp$/) {
		INetSim::Chargen::UDP->run;
	    }
	    elsif(/^quotd_tcp$/) {
		INetSim::Quotd::TCP->run;
	    }
	    elsif(/^quotd_udp$/) {
		INetSim::Quotd::UDP->run;
	    }
	    elsif(/^tftp$/) {
		INetSim::TFTP->run;
	    }
	    elsif(/^finger$/) {
		INetSim::Finger->run;
	    }
	    elsif(/^dummy_tcp$/) {
		INetSim::Dummy::TCP->run;
	    }
	    elsif(/^dummy_udp$/) {
		INetSim::Dummy::UDP->run;
	    }
	    elsif(/^ftp$/) {
		INetSim::FTP->run;
	    }
	    elsif(/^ftps$/) {
		INetSim::FTP->new({ SSL => 1 })->run;
	    }
	    elsif(/^syslog$/) {
		INetSim::Syslog->run;
	    }
	    elsif(/^irc$/) {
		INetSim::IRC->run;
	    }
	    elsif(/^ircs$/) {
		INetSim::IRC->run( SSL => 1 );
	    }
	}
	else {
	    &error_exit ("Could not fork: $!", 1);
	}
    }
    sleep 1;
}


sub handle_pid {
    my $cmd = shift;
    my $pidfile = &INetSim::CommandLine::getCommandLineOption("pidfile");

    $pidfile =~ /(.*)/; # evil untaint
    $pidfile = $1;
    if ($cmd eq "create") {
        if (-f $pidfile) {
	    print STDOUT "PIDfile '$pidfile' exists - INetSim already running?\n";
	    exit 1;
	}
	else {
	    if (! open (PIDFILE, "> $pidfile")) {
		print STDOUT "Unable to open PIDfile for writing: $!\n";
		exit 1;
	    }
	    print PIDFILE $PPID;
	    close PIDFILE;
	}
    }
    elsif ($cmd eq "remove") {
        if (-f $pidfile) {
	    unlink $pidfile;
	}
	else {
	    print STDOUT "Hmm, PIDfile '$pidfile' not found (but, who cares?)\n";
	}
    }
}


sub auto_faketime {
    if (&INetSim::Config::getConfigParameter("Faketime_AutoDelay") > 0) {
	my $pid = fork();
	if ($pid) {
	    # we are the parent process
	    push(@childs, $pid);
	}
	elsif ($pid == 0){
	    # we are the child process
	    &INetSim::FakeTime::auto_faketime();
	}
    }
}


sub redirect_packets {
    if (&INetSim::Config::getConfigParameter("Redirect_Enabled")) {
        # check for linux
        if ($^O !~ /linux/i) {
            &INetSim::Log::MainLog("failed! Error: Sorry, the Redirect module does not support this operating system!", "redirect");
            return 0;
        }
        # check for Perlipq library
        eval {
               eval "use IPTables::IPv4::IPQueue; 1" or die;
        };
        if ($@) {
            &INetSim::Log::MainLog("failed! Error: Sorry, this module requires the Perlipq library (IPTables::IPv4::IPQueue)!", "redirect");
            return 0;
        }
        # check for redirect module
        eval {
               eval "use INetSim::Redirect; 1" or die;
        };
        if ($@) {
            &INetSim::Log::MainLog("failed! Error: $@", "redirect");
            return 0;
        }
        my $pid = fork();
        if ($pid) {
	    # we are the parent process
	    push(@childs, $pid);
        }
        elsif ($pid == 0){
	    # we are the child process
	    &INetSim::Redirect::run();
        }
    }
}


sub rest_in_peace {
    my $count = @childs;
    my $i;

    for ($i = 0; $i < $count; $i++) {
        waitpid(-1,&WNOHANG);
        if (! (kill (0, $childs[$i]))) {
            splice (@childs, $i, 1);
            $count = @childs;
            $i--;
        }
    }
}


sub wait_pids {
    wait();
    foreach (@childs){
	waitpid($_, 0);
    }
}


sub kill_pids {
    foreach (@childs){
	kill("TERM", $_);
	waitpid($_, 0);
    }
}


sub error_exit {
    my $msg = shift;
    if (! defined $msg) {
	$msg = "Unknown error";
    }
    my $exitcode = shift;
    if (! defined $exitcode) {
	$exitcode = 1;
    }
    elsif (($exitcode !~ /^[\d]{1,3}$/) || (int($exitcode) < 0) || (int($exitcode > 255))) {
	print STDOUT "Illegal exit code!\n";
	$exitcode = 1;
    }

    print STDOUT "Error: $msg.\n";

    &kill_pids;
    &wait_pids;
    &handle_pid("remove");

    exit 1;
}


#############################################################
# Main
#

sub main {
    # Parse commandline options
    &INetSim::CommandLine::parse_options();

    # Check command line option 'help'
    if (&INetSim::CommandLine::getCommandLineOption("help")) {
	print STDOUT << "EOF";
$VERSION by Matthias Eckert & Thomas Hungenberg

Usage: $0 [options]

Available options:
  --help                         Print this help message.
  --version                      Show version information.
  --config=<filename>            Configuration file to use.
  --log-dir=<directory>          Directory logfiles are written to.
  --data-dir=<directory>         Directory containing service data.
  --report-dir=<directory>       Directory reports are written to.
  --bind-address=<IP address>    Default IP address to bind services to.
                                 Overrides configuration option 'default_bind_address'.
  --max-childs=<num>             Default maximum number of child processes per service.
                                 Overrides configuration option 'default_max_childs'.
  --user=<username>              Default user to run services.
                                 Overrides configuration option 'default_run_as_user'.
  --faketime-init-delta=<secs>   Initial faketime delta (seconds).
                                 Overrides configuration option 'faketime_init_delta'.
  --faketime-auto-delay=<secs>   Delay for auto incrementing faketime (seconds).
                                 Overrides configuration option 'faketime_auto_delay'.
  --faketime-auto-incr=<secs>    Delta for auto incrementing faketime (seconds).
                                 Overrides configuration option 'faketime_auto_increment'.
  --session=<id>                 Session id to use. Defaults to main process id.
  --pidfile=<filename>           Pid file to use. Defaults to '/var/run/inetsim.pid'.

EOF
;
	exit 0;
    }
    elsif (&INetSim::CommandLine::getCommandLineOption("version")) {
        print STDOUT "$VERSION by Matthias Eckert & Thomas Hungenberg\n";
        exit 0;
    }


    # Check if we are running with root privileges (EUID 0)
    if ( $> != 0 ) {
	print STDOUT "Sorry, this program must be started as root!\n";
	exit 1;
    }

    # Check if group "inetsim" exists on system
    my $gid = getgrnam("inetsim");
    if (! defined $gid) {
	print STDOUT "No such group 'inetsim' configured on this system!\n";
	print STDOUT "Please create group and start again. See documentation for more information.\n";
	exit 1;
    }

    print STDOUT "$VERSION by Matthias Eckert & Thomas Hungenberg\n";

    # create pidfile
    &handle_pid("create");

    # Parse configuration file
    &INetSim::Config::parse_config;

    # Check if there are services to start configured, else exit
    if (! scalar(&INetSim::Config::getServicesToStart())) {
	&INetSim::Log::MainLog("No services to start configured. Exiting.");
	&handle_pid("remove");
	exit 0;
    }

    # ignore some signal handlers during startup
    local $SIG{'INT'} = 'IGNORE';
    local $SIG{'HUP'} = 'IGNORE';
    local $SIG{'TERM'} = 'IGNORE';

    &INetSim::Log::MainLog("=== INetSim main process started (PID $PPID) ===");
    &INetSim::Log::MainLog("Session ID:     " . &INetSim::Config::getConfigParameter("SessionID"));
    &INetSim::Log::MainLog("Listening on:   " . &INetSim::Config::getConfigParameter("Default_BindAddress"));
    &INetSim::Log::MainLog("Real Date/Time: " . strftime "%Y-%m-%d %H:%M:%S", localtime);
    &INetSim::Log::MainLog("Fake Date/Time: " . (strftime "%Y-%m-%d %H:%M:%S", localtime(&INetSim::FakeTime::get_faketime())). " (Delta: " . &INetSim::Config::getConfigParameter("Faketime_Delta") . " seconds)");
    &INetSim::Log::MainLog(" Forking services...");
    &fork_services();
    &auto_faketime();
    &redirect_packets();

    if ($$ == $PPID) {
	$0 = 'inetsim_main';
	sleep 2;
        # reap zombies ;-)
        &rest_in_peace;
	&INetSim::Log::MainLog(" done.");
	&INetSim::Log::MainLog("Simulation running.");
	# catch up some signalhandlers for the parent process
	local $SIG{'INT'} = sub {&kill_pids;};
	local $SIG{'HUP'} = sub {&kill_pids;};
	local $SIG{'TERM'} = sub {&kill_pids;};
	&wait_pids;
	&INetSim::Log::MainLog("Simulation stopped.");

	# create report
	if (&INetSim::Config::getConfigParameter("Create_Reports")) {
	    &INetSim::Report::GenReport;
	}

	&INetSim::Log::MainLog("=== INetSim main process stopped (PID $PPID) ===");
	&INetSim::Log::MainLog(".");
    }

    # delete pidfile
    &handle_pid("remove");
    exit 0;
}


1;
#############################################################
#
# History:
#
# Version 1.2.4 (2013-08-14) th
# - changed date/time output format
#
# Version 1.2beta5 (2010-04-15) me
# - added 'Default_BindAddress' to startup screen
#
# Version 1.2beta4 (2009-12-15) th
#
# Version 1.2beta3 (2009-09-23) me  [branch]
# - added service IRC/IRCs
#
# Version 1.1.1 (2009-09-09) th
# - 1.1.1 release
#
# Version 1.2beta2 (2009-09-04) me  [branch]
# - services POP3, HTTP and FTP prepared for using SSL too
#
# Version 1.2beta1 (2009-09-03) me  [branch]
# - added service SMTPS
# - added commandline option '--version' to help output
#
# Version 1.1 (2008-10-12) me
# - 1.1 release
#
# Version 1.1pre4 (2008-09-08) me
# - added service syslog
#
# Version 1.1pre3 (2008-08-24) me
# - changed FTP module name
#
# Version 1.1pre2 (2008-08-20) me
# - added service FTP
#
# Version 1.1pre1 (2008-08-09) th
# - added configuration option 'Create_Reports'
#
# Version 1.0 (2008-07-06) th
# - 1.0 release
#
# Version 1.0rc4 (2008-06-26) th
# - 1.0 rc4 release
#
# Version 1.0rc4pre9 (2008-03-20) me
# - fixed checks in function redirect_packets()
#
# Version 1.0rc4pre8 (2008-03-19) me
# - changed handling for OS check and added an error message
# - removed check for use of 'INetSim::Redirect' (see line below)
# - added check for use of 'IPTables::IPv4::IPQueue' instead of
#   the redirect module and added an error message
# - added function rest_in_peace() to get possible zombies
#
# Version 1.0rc4pre7 (2008-03-17) me
# - added &INetSim::Config::getConfigParameter("Redirect_Enabled") in
#   function redirect_packets()
#
# Version 1.0rc4pre6 (2008-03-15) me
# - added check for use of 'INetSim::Redirect', because it's
#   system dependent
# - added check for operating system in function redirect_packets()
#
# Version 1.0rc4pre5 (2008-03-07) me
# - added service "redirect"
#
# Version 1.0rc4pre4 (2008-03-06) me
# - added service "dummy"
#
# Version 1.0rc4pre3 (2008-03-05) me
# - moved checks for uid '0' and group 'inetsim' below commandline
#   parser, because '--help' should always be possible
#
# Version 1.0rc4pre2 (2008-02-17) me
# - replaced variable 'pidfile' with
#   &INetSim::CommandLine::getCommandLineOption("pidfile");
# - unused old code in function 'handle_pid' removed
#
# Version 1.0rc4pre1 (2007-12-31) th
# - change process names
#
# Version 1.0rc3 (2007-12-12) me
# - new public release
#
# Version 1.0rc3pre1 (2007-11-07) me
# - added service finger
#
# Version 1.0rc2 (2007-10-21) th
# - new public release
#
# Version 1.0rc1 (2007-10-17) th
# - first public release
#
# Version 0.41   (2007-05-31) th
# - added/removed some comments
#
# Version 0.40   (2007-05-23) th
# - added 'sleep 1' to main process to wait for all services started
#
# Version 0.39   (2007-04-30) th
# - check if group 'inetsim' exists on system
# - use getServicesToStart() instead of accessing module
#   variables in Config.pm
#
# Version 0.38   (2007-04-29) th
# - added module CommandLine.pm
# - added check for command line option 'help'
# - added global variable 'VERSION'
#
# Version 0.37   (2007-04-25) th
# - replaced &INetSim::FakeTime::get_faketime_delta() with
#   &INetSim::Config::getConfigParameter("faketime_delta")
#
# Version 0.36   (2007-04-22) th
# - added function error_exit()
# - renamed parameter options in handle_pid() to "create" and "remove"
#
# Version 0.35   (2007-04-21) me
# - added GenReport()
#
# Version 0.34   (2007-04-20) me
# - added check for uid 0
#
# Version 0.33   (2007-04-20) me
# - added function for pidfile handling
#
# Version 0.32   (2007-04-20) me
# - added logging of $INetSim::Config::SessionID
# - re-added a dot at the end of main log
#   (this makes the log easier to read)
#
# Version 0.31   (2007-04-10) th
# - renamed fork_servers() to fork_services()
# - added auto_faketime()
#
# Version 0.30   (2007-04-09) th
# - added module FakeTime
#
# Version 0.30   (2007-04-05) th
# - changed module name 'dns.pm' to 'DNS.pm'
#
# Version 0.29   (2007-03-30) me
# - added service tftp
#
# Version 0.28   (2007-03-27) th
# - moved CONFIGFILENAME, MAINLOGFILENAME and
#   SUBLOGFILENAME to INetSim::Config
# - moved logging functions to INetSim::Log
#
# Version 0.27   (2007-03-26) th
# - changed daytime_tcp to use INetSim::GenericServer
# - changed daytime_udp to use INetSim::GenericServer
# - changed time_tcp to use INetSim::GenericServer
# - changed time_udp to use INetSim::GenericServer
# - changed quotd_tcp to use INetSim::GenericServer
# - changed quotd_udp to use INetSim::GenericServer
# - changed discard_tcp to use INetSim::GenericServer
# - changed discard_udp to use INetSim::GenericServer
# - changed smtp to use INetSim::GenericServer
# - changed pop3 to use INetSim::GenericServer
#
# Version 0.26   (2007-03-24) th
# - changed chargen_tcp to use INetSim::GenericServer
# - changed chargen_udp to use INetSim::GenericServer
# - changed http to use INetSim::GenericServer
#
# Version 0.25   (2007-03-23) th
# - changed echo_tcp to use INetSim::GenericServer
# - changed echo_udp to use INetSim::GenericServer
#
# Version 0.24   (2007-03-19) th
# - added service http
#
# Version 0.23   (2007-03-19) me
# - added service ident
# - added service echo
# - added service discard
# - added service chargen
# - added service discard
#
# Version 0.22   (2007-03-16) th
# - added configuration option @INetSim::Config::ServicesToStart
# - changed BASEDIR to "."
#
# Version 0.21   (2007-03-15) me
# - ignore signals during startup
#
# Version 0.2    (2007-03-15) th
# - added configuration module
# - rewrote fork_servers()
# - changed logfile location
#
# Version 0.1    (2007-03-12) me
#
#############################################################
