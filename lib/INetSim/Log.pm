# -*- perl -*-
#
# INetSim::Log - INetSim logging
#
# (c)2007-2013 Matthias Eckert, Thomas Hungenberg
#
# Version 0.37  (2013-08-15)
#
# For history/changelog see bottom of this file.
#
#############################################################

package INetSim::Log;

use strict;
use warnings;
use Fcntl ':mode';

my $mainlogfilename;
my $sublogfilename;
my $debuglogfilename;
my $DEBUG = 0;
my $SID = undef;


sub init {
    my $dummy = &INetSim::Config::getConfigParameter("MainLogfileName");
    $dummy =~ /^(.*)$/; # evil untaint!
    $mainlogfilename = $1;
    $dummy = &INetSim::Config::getConfigParameter("SubLogfileName");
    $dummy =~ /^(.*)$/; # evil untaint!
    $sublogfilename = $1;
    $dummy = &INetSim::Config::getConfigParameter("DebugLogfileName");
    $dummy =~ /^(.*)$/; # evil untaint!
    $debuglogfilename = $1;

    # check if MainLogfile exists
    if (! -f $mainlogfilename) {
	# if not, create it
	print STDOUT "Main logfile '$mainlogfilename' does not exist. Trying to create it...\n";
	if (open (MLOG, ">$mainlogfilename")) {
	    print STDOUT "Main logfile '$mainlogfilename' successfully created.\n";
	    close MLOG;
	    chmod 0660, $mainlogfilename;
	    my $gid = getgrnam("inetsim");
	    if (! defined $gid) {
		&INetSim::error_exit("Unable to get GID for group 'inetsim'");
	    }
	    chown -1, $gid, $mainlogfilename;
	}
	else {
	    &INetSim::error_exit("Unable to create main logfile '$mainlogfilename': $!");
	}
    }
    else {
	# check ownership and permissions
	my ($dev, $inode, $mode, $nlink, $uid, $gid, $rdev, $size, $atime, $mtime, $ctime, $blksize, $blocks) = stat $mainlogfilename;
        my $grpname = getgrgid $gid;
	# check for group owner 'inetsim'
	if ($grpname ne "inetsim") {
	    &INetSim::error_exit("Group owner of main logfile '$mainlogfilename' is not 'inetsim' but '$grpname'");
	}
	# check for group r/w permissions
	if ((($mode & 0060) >> 3) != 6) {
	    &INetSim::error_exit("No group r/w permissions on main logfile '$mainlogfilename'");
	}
    }


    # check if SubLogfile exists
    if (! -f $sublogfilename) {
	# if not, create it
	print STDOUT "Sub logfile '$sublogfilename' does not exist. Trying to create it...\n";
	if (open (MLOG, ">$sublogfilename")) {
	    print STDOUT "Sub logfile '$sublogfilename' successfully created.\n";
	    close MLOG;
	    chmod 0660, $sublogfilename;
	    my $gid = getgrnam("inetsim");
	    if (! defined $gid) {
		&INetSim::error_exit("Unable to get GID for group 'inetsim'");
	    }
	    chown -1, $gid, $sublogfilename;
	}
	else {
	    &INetSim::error_exit("Unable to create sub logfile '$sublogfilename': $!");
	}
    }
    else {
	# check ownership and permissions
	my ($dev, $inode, $mode, $nlink, $uid, $gid, $rdev, $size, $atime, $mtime, $ctime, $blksize, $blocks) = stat $sublogfilename;
        my $grpname = getgrgid $gid;
	# check for group owner 'inetsim'
	if ($grpname ne "inetsim") {
	    &INetSim::error_exit("Group owner of sub logfile '$sublogfilename' is not 'inetsim' but '$grpname'");
	}
	# check for group r/w permissions
	if ((($mode & 0060) >> 3) != 6) {
	    &INetSim::error_exit("No group r/w permissions on sub logfile '$sublogfilename'");
	}
    }


    # check if DebugLogfile exists
    if (! -f $debuglogfilename) {
	# if not, create it
	print STDOUT "Debug logfile '$debuglogfilename' does not exist. Trying to create it...\n";
	if (open (MLOG, ">$debuglogfilename")) {
	    print STDOUT "Debug logfile '$debuglogfilename' successfully created.\n";
	    close MLOG;
	    chmod 0660, $debuglogfilename;
	    my $gid = getgrnam("inetsim");
	    if (! defined $gid) {
		&INetSim::error_exit("Unable to get GID for group 'inetsim'");
	    }
	    chown -1, $gid, $debuglogfilename;
	}
	else {
	    &INetSim::error_exit("Unable to create debug logfile '$debuglogfilename': $!");
	}
    }
    else {
	# check ownership and permissions
	my ($dev, $inode, $mode, $nlink, $uid, $gid, $rdev, $size, $atime, $mtime, $ctime, $blksize, $blocks) = stat $debuglogfilename;
        my $grpname = getgrgid $gid;
	# check for group owner 'inetsim'
	if ($grpname ne "inetsim") {
	    &INetSim::error_exit("Group owner of debug logfile '$debuglogfilename' is not 'inetsim' but '$grpname'");
	}
	# check for group r/w permissions
	if ((($mode & 0060) >> 3) != 6) {
	    &INetSim::error_exit("No group r/w permissions on debug logfile '$debuglogfilename'");
	}
    }

    $DEBUG = &INetSim::Config::getConfigParameter("Debug");
}



sub MainLog{
    my $msg = shift || return 0;
    my $service = shift || "main";
    $msg =~ s/[\r\n]*$//g;
    my ($sec,$min,$hour,$mday,$mon,$year,$wday,$ydat,$isdst) = localtime();
    my $date = sprintf "%4d-%02d-%02d %02d:%02d:%02d", $year+1900,$mon+1,$mday,$hour,$min,$sec;

    if (! open (MLOG, ">>$mainlogfilename")) {
	&INetSim::error_exit("Unable to open main logfile '$mainlogfilename': $!");
    }

    select MLOG;
    $| = 1;
    if ($service ne "main") {
	print MLOG "[$date]    * $service $msg\n";
	$msg =~ s/failed\!/\033\[31\;1mfailed\!\033\[0m/;
	print STDOUT "  * $service - $msg\n";
    }
    else {
	print MLOG "[$date]  $msg\n";
	$msg =~ s/failed\!/\033\[31\;1mfailed\!\033\[0m/;
	print STDOUT "$msg\n";
    }
    close MLOG;
}



sub SubLog{
    my ($msg, $service, $cpid) = @_;
    ($msg && $service && $cpid) or return;
    $msg =~ s/[\r\n]*$//g;
    my ($sec,$min,$hour,$mday,$mon,$year,$wday,$ydat,$isdst) = localtime(&INetSim::FakeTime::get_faketime());
    my $fakedate = sprintf "%4d-%02d-%02d %02d:%02d:%02d", $year+1900,$mon+1,$mday,$hour,$min,$sec;

    if (! open (SLOG, ">>$sublogfilename")) {
        &INetSim::error_exit("Unable to open sub logfile '$sublogfilename': $!");
    }
    select SLOG;
    $| = 1;
    # replace non-printable characters with "."
    $msg =~ s/([^\x20-\x7e])/\./g;
    (!$SID) && ($SID = &INetSim::Config::getConfigParameter("SessionID"));
    print SLOG "[$fakedate] [$SID] [$service $cpid] $msg\n";
    close SLOG;
}



sub DebugLog{
    ($DEBUG) or return;
    my ($msg, $service, $cpid) = @_;
    ($msg && $service && $cpid) or return;
    $msg =~ s/[\r\n]*$//g;
    my ($sec,$min,$hour,$mday,$mon,$year,$wday,$ydat,$isdst) = localtime(&INetSim::FakeTime::get_faketime());
    my $fakedate = sprintf "%4d-%02d-%02d %02d:%02d:%02d", $year+1900,$mon+1,$mday,$hour,$min,$sec;

    if (! open (DLOG, ">>$debuglogfilename")) {
        &INetSim::error_exit("Unable to open debug logfile '$debuglogfilename': $!");
    }
    select DLOG;
    $| = 1;
    # replace non-printable characters with "."
    $msg =~ s/([^\x20-\x7e])/\./g;
    (!$SID) && ($SID = &INetSim::Config::getConfigParameter("SessionID"));
    print DLOG "[$fakedate] [$SID] [$service $cpid] $msg\n";
    close DLOG;
}



1;
#############################################################
#
# History:
#
# Version 0.37  (2013-08-15) th
# - use correct session ID in service.log
#
# Version 0.36  (2009-10-30) me
# - replace non-printable characters with "."
#
# Version 0.35  (2009-10-29) me
# - small optimisations - mostly in functions SubLog() and DebugLog()
#
# Version 0.34  (2008-09-01) me
# - changed column of process id in functions SubLog() and DebugLog()
#
# Version 0.33  (2008-08-27) me
# - added logging of process id in functions SubLog() and DebugLog()
#
# Version 0.32  (2007-05-02) th
# - merged versions 0.30b and 0.31
#
# Version 0.31  (2007-04-30) th
# - check group owner and permissions of logfiles
#
# Version 0.30b (2007-04-28) me
# - added function DebugLog
#
# Version 0.30  (2007-04-29) th
# - added init function
# - check if logfiles exist, otherwise create them
#
# Version 0.29  (2007-04-27) th
# - use getConfigParameter
#
# Version 0.28  (2007-04-24) th
# - fixed deep recursion if logfiles cannot be opened
#
# Version 0.27  (2007-04-22) th
# - separate $service and $msg by "-" in SubLog
#
# Version 0.26  (2007-04-20) me
# - added logging of $INetSim::Config::SessionID in SubLog
#
# Version 0.25  (2007-04-19) me
# - eye-catcher for "failed!" messages added
#
# Version 0.24  (2007-04-13) th
# - removed logging of real date/time in SubLog
#
# Version 0.23  (2007-04-10) th
# - get fake time via &INetSim::FakeTime::get_faketime()
#   instead of accessing $INetSim::Config::FakeTimeDelta
#
# Version 0.22  (2007-04-09) th
# - added logging of faketime in SubLog
#
# Version 0.21  (2007-04-06) th
# - added blanks in sublog output
#
# Version 0.2   (2007-03-27) th
# - moved logging functions from main program to this module
#
#############################################################
