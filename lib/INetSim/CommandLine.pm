# -*- perl -*-
#
# INetSim::CommandLine - INetSim command line parser
#
# (c)2007-2009 Thomas Hungenberg, Matthias Eckert
#
# Version 0.4  (2009-08-27)
#
# For history/changelog see bottom of this file.
#
#############################################################

package INetSim::CommandLine;

use strict;
use warnings;
use Getopt::Long;


my %CommandLineOptions = ();

# compiled regular expressions for matching strings
my $RE_signedInt = qr/^[-]{0,1}[\d]+$/;
my $RE_unsignedInt = qr/^[\d]+$/;
my $RE_printable = qr/^[\x20-\x7e]+$/;
my $RE_validIP = qr/^(([01]?[0-9][0-9]?|2[0-4][0-9]|25[0-5])\.){3}([01]?[0-9][0-9]?|2[0-4][0-9]|25[0-5])$/;
my $RE_validHostname = qr/^[a-zA-Z0-9]([-a-zA-Z0-9]*[a-zA-Z0-9]|)$/;
my $RE_validDomainname = qr/^([a-zA-Z0-9]([-a-zA-Z0-9]*[a-zA-Z0-9]|)\.)*[a-zA-Z]+$/;
my $RE_validFQDNHostname = qr/^([a-zA-Z0-9]([-a-zA-Z0-9]*[a-zA-Z0-9]|)\.)+[a-zA-Z]+$/;
my $RE_validPathFilename = qr/^[a-zA-Z0-9\.\-\_\/]+$/;
my $RE_validSession = qr/^[a-zA-Z0-9\.\-\_\/]+$/;

sub parse_options {
    &Getopt::Long::Configure('pass_through', 'prefix_pattern=--');
    my $result = GetOptions (
			     'help'		     => \$CommandLineOptions{'help'},
			     'version'		     => \$CommandLineOptions{'version'},
			     'log-dir=s'	     => \$CommandLineOptions{'log_dir'},
			     'data-dir=s'	     => \$CommandLineOptions{'data_dir'},
			     'report-dir=s'	     => \$CommandLineOptions{'report_dir'},
			     'config=s' 	     => \$CommandLineOptions{'config'},
			     'bind-address=s'	     => \$CommandLineOptions{'bind_address'},
			     'max-childs=s'	     => \$CommandLineOptions{'max_childs'},
			     'user=s'		     => \$CommandLineOptions{'user'},
			     'faketime-init-delta=s' => \$CommandLineOptions{'faketime_initdelta'},
			     'faketime-auto-delay=s' => \$CommandLineOptions{'faketime_autodelay'},
			     'faketime-auto-incr=s'  => \$CommandLineOptions{'faketime_autoincr'},
			     'session=s'	     => \$CommandLineOptions{'session'},
			     'pidfile=s'	     => \$CommandLineOptions{'pidfile'}
			     );

    if ($#ARGV > -1) {
	# unknown options
	foreach (@ARGV) {
	    print STDOUT "Unknown command line option '$_'.\n";
	}
	print STDOUT "See '$0 --help' for a list of available options.\n";
	exit 1;
    }

    # check log-dir
    if (defined $CommandLineOptions{'log_dir'}) {
	if ($CommandLineOptions{'log_dir'} !~ $RE_validPathFilename) {
	    &cmdline_error("'$CommandLineOptions{'log_dir'}' is not a valid filepath name", "log-dir");
	}
	elsif (! -d $CommandLineOptions{'log_dir'}) {
	    &cmdline_error("directory '$CommandLineOptions{'log_dir'}' does not exist", "log-dir");
	}
	else {
	    $CommandLineOptions{'log_dir'} =~ s/[\/]+$//;
	    $CommandLineOptions{'log_dir'} .= "/";
	}
    }

    # check data-dir
    if (defined $CommandLineOptions{'data_dir'}) {
	if ($CommandLineOptions{'data_dir'} !~ $RE_validPathFilename) {
	    &cmdline_error("'$CommandLineOptions{'data_dir'}' is not a valid filepath name", "data-dir");
	}
	elsif (! -d $CommandLineOptions{'data_dir'}) {
	    &cmdline_error("directory '$CommandLineOptions{'data_dir'}' does not exist", "data-dir");
	}
	else {
	    $CommandLineOptions{'data_dir'} =~ s/[\/]+$//;
	    $CommandLineOptions{'data_dir'} .= "/";
	}
    }

    # check report-dir
    if (defined $CommandLineOptions{'report_dir'}) {
	if ($CommandLineOptions{'report_dir'} !~ $RE_validPathFilename) {
	    &cmdline_error("'$CommandLineOptions{'report_dir'}' is not a valid filepath name", "report-dir");
	}
	elsif (! -d $CommandLineOptions{'report_dir'}) {
	    &cmdline_error("directory '$CommandLineOptions{'report_dir'}' does not exist", "report-dir");
	}
	else {
	    $CommandLineOptions{'report_dir'} =~ s/[\/]+$//;
	    $CommandLineOptions{'report_dir'} .= "/";
	}
    }

    # check config
    if ((defined $CommandLineOptions{'config'}) && ($CommandLineOptions{'config'} !~ $RE_validPathFilename)) {
	&cmdline_error("'$CommandLineOptions{'config'}' is not a valid filename", "config");
    }

    # check bind-address
    if ((defined $CommandLineOptions{'bind_address'}) && ($CommandLineOptions{'bind_address'} !~ $RE_validIP)) {
	&cmdline_error("'$CommandLineOptions{'bind_address'}' is not a valid IP address", "bind-address");
    }

    # check max-childs
    if (defined $CommandLineOptions{'max_childs'}) {
	if (($CommandLineOptions{'max_childs'} !~ $RE_signedInt) || ($CommandLineOptions{'max_childs'} < 1) || ($CommandLineOptions{'max_childs'} > 30)) {
	    &cmdline_error("'$CommandLineOptions{'max_childs'}' is not an integer value of range [1..30]", "max_childs");
	}
    }

    # check user
    if (defined $CommandLineOptions{'user'}) {
	if ($CommandLineOptions{'user'} !~ $RE_printable) {
	    &cmdline_error("'$CommandLineOptions{'user'}' is not a valid username", "user");
	}
	else {
	    my $uid = getpwnam($CommandLineOptions{'user'});
	    if (! defined $uid) {
		# username does not exist
		&cmdline_error("User '$CommandLineOptions{'user'}' does not exist on this system", "user");
	    }
	}
    }

    # check faketime-init-delta
    if (defined $CommandLineOptions{'faketime_initdelta'}) {
	if ($CommandLineOptions{'faketime_initdelta'} !~ $RE_signedInt) {
	    &cmdline_error("'$CommandLineOptions{'faketime_initdelta'}' is not numeric", "faketime-init-delta");
	}
	else {
	    # check if fake time is valid
	    my $cur_secs = time();
	    my $faketimemax = 2147483647;
	    if (($cur_secs + $CommandLineOptions{'faketime_initdelta'}) > $faketimemax) {
		&cmdline_error("Fake time exceeds maximum system time", "faketime-init-delta");
	    }
	    elsif (($cur_secs + $CommandLineOptions{'faketime_initdelta'}) < 0 ) {
		&cmdline_error("Fake time init delta too small", "faketime-init-delta");
	    }
	}
    }

    # check faketime-auto-delay
    if (defined $CommandLineOptions{'faketime_autodelay'}) {
	if (($CommandLineOptions{'faketime_autodelay'} !~ $RE_signedInt) || ($CommandLineOptions{'faketime_autodelay'} < 0) || ($CommandLineOptions{'faketime_autodelay'} > 86400)) {
	    &cmdline_error("'$CommandLineOptions{'faketime_autodelay'}' is not an integer value of range [0..86400]", "faketime-auto-delay");
	}
    }

    # check faketime-auto-incr
    if (defined $CommandLineOptions{'faketime_autoincr'}) {
	if (($CommandLineOptions{'faketime_autoincr'} !~ $RE_signedInt) || ($CommandLineOptions{'faketime_autoincr'} < -31536000) || ($CommandLineOptions{'faketime_autoincr'} > 31536000)) {
	    &cmdline_error("'$CommandLineOptions{'faketime_autoincr'}' is not an integer value of range [-31536000..31536000]", "faketime-auto-incr");
	}
    }

    # check session
    if ((defined $CommandLineOptions{'session'}) && ($CommandLineOptions{'session'} !~ $RE_validSession)) {
	&cmdline_error("'$CommandLineOptions{'session'}' is not a valid session identifier", "session");
    }
    
    # check pid file
    if ((defined $CommandLineOptions{'pidfile'}) && ($CommandLineOptions{'pidfile'} !~ $RE_validPathFilename)) {
        &cmdline_error("'$CommandLineOptions{'pidfile'}' is not a valid pid filename", "pidfile");
    }
    # set default pid file if unset
    if ((! defined $CommandLineOptions{'pidfile'}) || (! $CommandLineOptions{'pidfile'})) {
        $CommandLineOptions{'pidfile'} = "/var/run/inetsim.pid";
    }
}


sub cmdline_warn {
    my $msg = shift;
    my $opt = shift;
    &INetSim::Log::MainLog("Warning: " . $msg . " at option '$opt'.");
}


sub cmdline_error {
    my $msg = shift;
    my $opt = shift;
    print STDOUT "Error in command line option '$opt': $msg!\n";
    exit 1;
}


sub getCommandLineOption {
    my $key = shift;
    if (! defined $key) {
	# programming error -> exit
	&INetSim::error_exit("getCommandLineOption() called without parameter.");
    }
    elsif (exists $CommandLineOptions{$key}) {
            return $CommandLineOptions{$key};
    }
    else {
	# programming error -> exit
	&INetSim::error_exit("No such command line option '$key'.");
    }
}


1;
#############################################################
#
# History:
#
# Version 0.4   (2009-08-27) me
# - added commandline option 'version'
#
# Version 0.3   (2008-02-17) me
# - added commandline option 'pidfile'
#
# Version 0.2   (2007-04-30) th
# - mostly rewrote parser checks
# - check for unknown commandline options
#
# Version 0.1   (2007-04-29) th
# - moved command line parser from Config.pm to this module
# - added function getCommandLineOption()
#
#############################################################
