# -*- perl -*-
#
# INetSim::POP3 - A fake POP3 server
#
# RFC 1939 - Post Office Protocol - Version 3
#
# (c)2007-2014 Matthias Eckert, Thomas Hungenberg
#
# Version 0.106 (2014-05-23)
#
# For history/changelog see bottom of this file.
#
#############################################################

package INetSim::POP3;

use strict;
use warnings;
use base qw(INetSim::GenericServer);
use Digest::SHA;
use MIME::Base64;
#use Fcntl ':mode';

my $SSL = 0;
eval { require IO::Socket::SSL; };
if (! $@) { $SSL = 1; };


# http://www.iana.org/assignments/pop3-extension-mechanism
my %CAPA_AVAIL = (	"TOP"			=>	1,	# RFC 1939, 2449
			"USER"			=>	1,	# RFC 1939, 2449
			"SASL"			=>	2,	# RFC 2449, 1734, 5034, 2195 ... (http://www.iana.org/assignments/sasl-mechanisms)
			"RESP-CODES"		=>	1,	# RFC 2449
			"LOGIN-DELAY"		=>	2,	# RFC 2449
			"PIPELINING"		=>	0,	# RFC 2449
			"EXPIRE"		=>	2,	# RFC 2449
			"UIDL"			=>	1,	# RFC 1939, 2449
			"IMPLEMENTATION"	=>	2,	# RFC 2449
			"AUTH-RESP-CODE"	=>	1,	# RFC 3206
			"STLS"			=>	1	# RFC 2595
);
# status: 10 of 11
#
# Note: APOP is not listed as capability here (see RFC 2449 section 6.0 for more details)


my %POP3_CAPA;

my @MBOX;

my %status;



sub configure_hook {
    my $self = shift;
    my ($dev, $inode, $mode, $nlink, $uid, $gid, $rdev, $size, $atime, $mtime, $ctime, $blksize, $blocks, $grpname) = undef;

    $self->{server}->{host}   = &INetSim::Config::getConfigParameter("Default_BindAddress"); # bind to address
    $self->{server}->{proto}  = 'tcp';                                      # TCP protocol
    $self->{server}->{user}   = &INetSim::Config::getConfigParameter("Default_RunAsUser");       # user to run as
    $self->{server}->{group}  = &INetSim::Config::getConfigParameter("Default_RunAsGroup");    # group to run as
    $self->{server}->{setsid} = 0;                                   # do not daemonize
    $self->{server}->{no_client_stdout} = 1;                         # do not attach client to STDOUT
    $self->{server}->{log_level} = 0;                                # do not log anything
    # cert directory
    $self->{cert_dir} = &INetSim::Config::getConfigParameter("CertDir");

    if (defined $self->{server}->{'SSL'} && $self->{server}->{'SSL'}) {
        $self->{servicename} = &INetSim::Config::getConfigParameter("POP3S_ServiceName");
        if (! $SSL) {
            &INetSim::Log::MainLog("failed! Library IO::Socket::SSL not installed", $self->{servicename});
            exit 1;
        }
        $self->{ssl_key} = $self->{cert_dir} . (defined &INetSim::Config::getConfigParameter("POP3S_KeyFileName") ? &INetSim::Config::getConfigParameter("POP3S_KeyFileName") : &INetSim::Config::getConfigParameter("Default_KeyFileName"));
        $self->{ssl_crt} = $self->{cert_dir} . (defined &INetSim::Config::getConfigParameter("POP3S_CrtFileName") ? &INetSim::Config::getConfigParameter("POP3S_CrtFileName") : &INetSim::Config::getConfigParameter("Default_CrtFileName"));
        $self->{ssl_dh} = (defined &INetSim::Config::getConfigParameter("POP3S_DHFileName") ? &INetSim::Config::getConfigParameter("POP3S_DHFileName") : &INetSim::Config::getConfigParameter("Default_DHFileName"));
        if (! -f $self->{ssl_key} || ! -r $self->{ssl_key} || ! -f $self->{ssl_crt} || ! -r $self->{ssl_crt} || ! -s $self->{ssl_key} || ! -s $self->{ssl_crt}) {
            &INetSim::Log::MainLog("failed! Unable to read SSL certificate files", $self->{servicename});
            exit 1;
        }
        $self->{ssl_enabled} = 1;
        $self->{server}->{port}   = &INetSim::Config::getConfigParameter("POP3S_BindPort");  # bind to port
        $self->{mboxdirname} = &INetSim::Config::getConfigParameter("POP3S_MBOXDirName");
        $self->{datfile} = $self->{mboxdirname} . "/pop3s.data";
        $self->{sessionlockfile} = $self->{mboxdirname} . "/pop3s.lock";
        $self->{sessiondatfile} = $self->{mboxdirname} . "/pop3s.session";
        $self->{version} = &INetSim::Config::getConfigParameter("POP3S_Version");
        $self->{banner} = &INetSim::Config::getConfigParameter("POP3S_Banner");
        $self->{hostname} = &INetSim::Config::getConfigParameter("POP3S_Hostname");
        $self->{enable_apop} = &INetSim::Config::getConfigParameter("POP3S_EnableAPOP");
        $self->{capabilities} = &INetSim::Config::getConfigParameter("POP3S_EnableCapabilities");
        $self->{auth_reversible_only} = &INetSim::Config::getConfigParameter("POP3S_AuthReversibleOnly");
        $self->{mbox_reread} = &INetSim::Config::getConfigParameter("POP3S_MBOXReRead");
        $self->{mbox_rebuild} = &INetSim::Config::getConfigParameter("POP3S_MBOXReBuild");
        $self->{mbox_maxmails} = &INetSim::Config::getConfigParameter("POP3S_MBOXMaxMails");
    }
    else {
        $self->{servicename} = &INetSim::Config::getConfigParameter("POP3_ServiceName");
        $self->{ssl_enabled} = 0;
        $self->{server}->{port}   = &INetSim::Config::getConfigParameter("POP3_BindPort");  # bind to port
        $self->{mboxdirname} = &INetSim::Config::getConfigParameter("POP3_MBOXDirName");
        $self->{datfile} = $self->{mboxdirname} . "/pop3.data";
        $self->{sessionlockfile} = $self->{mboxdirname} . "/pop3.lock";
        $self->{sessiondatfile} = $self->{mboxdirname} . "/pop3.session";
        $self->{version} = &INetSim::Config::getConfigParameter("POP3_Version");
        $self->{banner} = &INetSim::Config::getConfigParameter("POP3_Banner");
        $self->{hostname} = &INetSim::Config::getConfigParameter("POP3_Hostname");
        $self->{enable_apop} = &INetSim::Config::getConfigParameter("POP3_EnableAPOP");
        $self->{capabilities} = &INetSim::Config::getConfigParameter("POP3_EnableCapabilities");
        $self->{auth_reversible_only} = &INetSim::Config::getConfigParameter("POP3_AuthReversibleOnly");
        $self->{mbox_reread} = &INetSim::Config::getConfigParameter("POP3_MBOXReRead");
        $self->{mbox_rebuild} = &INetSim::Config::getConfigParameter("POP3_MBOXReBuild");
        $self->{mbox_maxmails} = &INetSim::Config::getConfigParameter("POP3_MBOXMaxMails");
        $self->{ssl_key} = $self->{cert_dir} . (defined &INetSim::Config::getConfigParameter("POP3_KeyFileName") ? &INetSim::Config::getConfigParameter("POP3_KeyFileName") : &INetSim::Config::getConfigParameter("Default_KeyFileName"));
        $self->{ssl_crt} = $self->{cert_dir} . (defined &INetSim::Config::getConfigParameter("POP3_CrtFileName") ? &INetSim::Config::getConfigParameter("POP3_CrtFileName") : &INetSim::Config::getConfigParameter("Default_CrtFileName"));
        $self->{ssl_dh} = (defined &INetSim::Config::getConfigParameter("POP3_DHFileName") ? &INetSim::Config::getConfigParameter("POP3_DHFileName") : &INetSim::Config::getConfigParameter("Default_DHFileName"));
    }

    # warn about missing dh file and disable
    if (defined $self->{ssl_dh} && $self->{ssl_dh}) {
        $self->{ssl_dh} = $self->{cert_dir} . $self->{ssl_dh};
        if (! -f $self->{ssl_dh} || ! -r $self->{ssl_dh}) {
            &INetSim::Log::MainLog("Warning: Unable to read Diffie-Hellman parameter file '$self->{ssl_dh}'", $self->{servicename});
            $self->{ssl_dh} = undef;
        }
    }

    # disable apop, if 'auth_reversible_only' is enabled
    if ($self->{auth_reversible_only} && $self->{enable_apop}) {
        $self->{enable_apop} = 0;
    }

    $self->{maxchilds} = &INetSim::Config::getConfigParameter("Default_MaxChilds");
    $self->{timeout} = &INetSim::Config::getConfigParameter("Default_TimeOut");

    $self->{mboxdirname} =~ /^(.*)$/; # evil untaint!
    $self->{mboxdirname} = $1;
    $self->{datfile} =~ /^(.*)$/; # evil untaint!
    $self->{datfile} = $1;
    $self->{sessionlockfile} =~ /^(.*)$/; # evil untaint!
    $self->{sessionlockfile} = $1;
    $self->{sessiondatfile} =~ /^(.*)$/; # evil untaint!
    $self->{sessiondatfile} = $1;

    $MBOX[0] = "";

    if (! open (DAT, ">> $self->{datfile}")) {
        &INetSim::Log::MainLog("Warning: Unable to open POP3 main data file file '$self->{datfile}': $!", $self->{servicename});
    }
    else {
        close DAT;
        chmod 0660, $self->{datfile};
        $gid = getgrnam("inetsim");
        if (! defined $gid) {
            &INetSim::Log::MainLog("Warning: Unable to get GID for group 'inetsim'", $self->{servicename});
        }
        chown -1, $gid, $self->{datfile};
        ($dev, $inode, $mode, $nlink, $uid, $gid, $rdev, $size, $atime, $mtime, $ctime, $blksize, $blocks) = stat $self->{datfile};
        $grpname = getgrgid $gid;
        # check for group owner 'inetsim'
        if ($grpname ne "inetsim") {
            &INetSim::Log::MainLog("Warning: Group owner of POP3 main datafile '$self->{datfile}' is not 'inetsim' but '$grpname'", $self->{servicename});
        }
        # check for group r/w permissions
        if ((($mode & 0060) >> 3) != 6) {
            &INetSim::Log::MainLog("Warning: No group r/w permissions on POP3 main datafile '$self->{datfile}'", $self->{servicename});
        }
    }

    if (! open (LCK, ">> $self->{sessionlockfile}")) {
        &INetSim::Log::MainLog("Warning: Unable to open POP3 lockfile file file '$self->{sessionlockfile}': $!", $self->{servicename});
    }
    else {
        close LCK;
        chmod 0660, $self->{sessionlockfile};
        $gid = getgrnam("inetsim");
        if (! defined $gid) {
            &INetSim::Log::MainLog("Warning: Unable to get GID for group 'inetsim'", $self->{servicename});
        }
        chown -1, $gid, $self->{sessionlockfile};
        ($dev, $inode, $mode, $nlink, $uid, $gid, $rdev, $size, $atime, $mtime, $ctime, $blksize, $blocks) = stat $self->{sessionlockfile};
        $grpname = getgrgid $gid;
        # check for group owner 'inetsim'
        if ($grpname ne "inetsim") {
            &INetSim::Log::MainLog("Warning: Group owner of POP3 lockfile '$self->{sessionlockfile}' is not 'inetsim' but '$grpname'", $self->{servicename});
        }
        # check for group r/w permissions
        if ((($mode & 0060) >> 3) != 6) {
            &INetSim::Log::MainLog("Warning: No group r/w permissions on POP3 lockfile '$self->{sessionlockfile}'", $self->{servicename});
        }
    }

    if (! open (SDAT, ">> $self->{sessiondatfile}")) {
        &INetSim::Log::MainLog("Warning: Unable to open POP3 session data file file '$self->{sessiondatfile}': $!", $self->{servicename});
    }
    else {
        close SDAT;
        chmod 0660, $self->{sessiondatfile};
        $gid = getgrnam("inetsim");
        if (! defined $gid) {
            &INetSim::Log::MainLog("Warning: Unable to get GID for group 'inetsim'", $self->{servicename});
        }
        chown -1, $gid, $self->{sessiondatfile};
        ($dev, $inode, $mode, $nlink, $uid, $gid, $rdev, $size, $atime, $mtime, $ctime, $blksize, $blocks) = stat $self->{sessiondatfile};
        $grpname = getgrgid $gid;
        # check for group owner 'inetsim'
        if ($grpname ne "inetsim") {
            &INetSim::Log::MainLog("Warning: Group owner of POP3 session datafile '$self->{sessiondatfile}' is not 'inetsim' but '$grpname'", $self->{servicename});
        }
        # check for group r/w permissions
        if ((($mode & 0060) >> 3) != 6) {
            &INetSim::Log::MainLog("Warning: No group r/w permissions on POP3 session datafile '$self->{sessiondatfile}'", $self->{servicename});
        }
    }

    # register configured (and available) capabilities
    $self->register_capabilities;
}


sub pre_loop_hook {
    my $self = shift;

    $0 = 'inetsim_' . $self->{servicename};
    &INetSim::Log::MainLog("started (PID $$)", $self->{servicename});
}


sub pre_server_close_hook {
    my $self = shift;

    $self->session_lock("unlock");
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
    my $line;

    $status{success} = 0;
    $status{auth_type} = "";
    $status{credentials} = "";
    $status{retrieved} = 0;
    $status{deleted} = 0;
    $status{tls_used} = 0;
    $status{tls_cipher} = "";

    if ($self->{ssl_enabled} && ! $self->upgrade_to_ssl()) {
        $self->slog_("connect");
        $self->slog_("info: Error setting up SSL:  $self->{last_ssl_error}");
        $self->slog_("disconnect");
    }
    elsif ($self->{server}->{numchilds} >= $self->{maxchilds}) {
        $self->slog_("connect");
        $self->send_("-ERR", "Maximum number of connections ($self->{maxchilds}) exceeded.");
        $self->slog_("disconnect");
    }
    else {
        $self->slog_("connect");
        ### Server Greeting
        if ($self->{enable_apop}) {
            $self->send_("+OK", "$self->{banner} <$$." . &INetSim::FakeTime::get_faketime() . "\@$self->{hostname}>");
        }
        else {
            $self->send_("+OK", "$self->{banner}");
        }
        # set variables/flags
        $self->{last_login} = 0;
        $self->{lock_error} = 0;
        $self->{state} = "auth";
        #
        srand(time() ^($$ + ($$ <<15)));

        eval {
            local $SIG{'ALRM'} = sub { die "TIMEOUT" };
            alarm($self->{timeout});
	    while ($line = <$client>){
	        ### 1. Waiting for Authorisation - The RFC calls this the Authentication State. Valid commands: USER PASS APOP QUIT
	        ### 2. After 1, switching to Transaction State. Valid commands: STAT LIST RETR DELE NOOP RSET UIDL QUIT
	        $line =~ s/^[\r\n\s\t]+//g;
	        $line =~ s/[\r\n\s\t]+$//g;
		alarm($self->{timeout});
	        $self->slog_("recv: $line");
	        ### Auth via USER/PASS
	        if ($line =~ /^USER(|([\s]+)(.*))$/i && defined $POP3_CAPA{USER}) {
		    $self->USER($3);
	        }
	        elsif ($line =~ /^PASS(|([\s]+)(.*))$/i && defined $POP3_CAPA{USER}) {
		    $self->PASS($3);
		    if ($self->{close_connection}) {
		        last;
		    }
	        }
	        ### Auth via APOP
		elsif ($line =~ /^APOP(|([\s]+)(.*))$/i && $self->{enable_apop}) {
		    $self->APOP($3);
		    if ($self->{close_connection}) {
		        last;
		    }
	        }
	        elsif ($line =~ /^QUIT(|([\s]+)(.*))$/i) {
		    $self->QUIT($3);
		    if ($self->{close_connection}) {
		        last;
		    }
	        }
	        elsif ($line =~ /^STAT(|([\s]+)(.*))$/i) {
		    $self->STAT($3);
	        }
	        elsif ($line =~ /^LIST(|([\s]+)(.*))$/i) {
		    $self->LIST($3);
	        }
	        elsif ($line =~ /^RETR(|([\s]+)(.*))$/i) {
                    $self->RETR($3);
	        }
	        elsif ($line =~ /^DELE(|([\s]+)(.*))$/i) {
		    $self->DELE($3);
	        }
	        elsif ($line =~ /^NOOP(|([\s]+)(.*))$/i) {
		    $self->NOOP($3);
	        }
	        elsif ($line =~ /^RSET(|([\s]+)(.*))$/i) {
		    $self->RSET($3);
	        }
	        elsif ($line =~ /^TOP(|([\s]+)(.*))$/i && defined $POP3_CAPA{TOP}) {
		    $self->TOP($3);
	        }
	        elsif ($line =~ /^UIDL(|([\s]+)(.*))$/i && defined $POP3_CAPA{UIDL}) {
		    $self->UIDL($3);
	        }
	        elsif ($line =~ /^CAPA(|([\s]+)(.*))$/i && $self->{capabilities}) {
		    $self->CAPA($3);
	        }
	        elsif ($line =~ /^AUTH(|([\s]+)(.*))$/i && defined $POP3_CAPA{SASL}) {
		    $self->AUTH($3);
		    if ($self->{close_connection}) {
		        last;
		    }
		}
	        elsif ($line =~ /^STLS(|([\s]+)(.*))$/i && defined $POP3_CAPA{STLS}) {
		    $self->STLS($3);
		    if ($self->{close_connection}) {
		        last;
		    }
	        }
		else {
		    $self->send_("-ERR", "Unknown command.");
		}
                alarm($self->{timeout});
	    }
            alarm(0);
        };
        if ($@ =~ /TIMEOUT/) {
            $self->send_("-ERR", "timeout exceeded");
            $self->slog_("disconnect (timeout)");
        }
        else {
            $self->slog_("disconnect");
        }
        if (! $self->{lock_error} && $self->session_lock()){
            $self->session_lock("unlock");
        }
    }
    if ($status{success}) {
        $self->slog_("stat: $status{success} retrieved=$status{retrieved} deleted=$status{deleted} auth=$status{auth_type} creds=$status{credentials} tls=$status{tls_used} cipher=$status{tls_cipher}");
    }
    else {
        $self->slog_("stat: $status{success}");
    }
}



sub slog_ {
    my ($self, $msg) = @_;
    my $rhost = $self->{server}->{peeraddr};
    my $rport = $self->{server}->{peerport};

    if (defined ($msg)) {
        $msg =~ s/[\r\n]*//;
        &INetSim::Log::SubLog("[$rhost:$rport] $msg", $self->{servicename}, $$);
    }
}



sub dlog_ {
    my ($self, $msg) = @_;
    my $rhost = $self->{server}->{peeraddr};
    my $rport = $self->{server}->{peerport};

    if (defined ($msg)) {
        $msg =~ s/[\r\n]*//;
        &INetSim::Log::DebugLog("[$rhost:$rport] $msg", $self->{servicename}, $$);
    }
}



sub send_ {
    my ($self, $code, $msg, $ecode) = @_;	# status code [+OK/-ERR] (required) ; message (required) ; extended status code (optional [RFC 2449, 3206])
    my $client = $self->{server}->{client};

    if (defined ($code) && defined ($msg)) {
        alarm($self->{timeout});
        $msg =~ s/[\r\n]*//;
        if ($code =~ /^(\+OK|\-ERR)$/) {
            if ($self->{capabilities} && $code =~ /^\-ERR$/ && defined $POP3_CAPA{"RESP-CODES"} && defined $ecode && $ecode ne "") {
                if ($ecode =~ /^IN\-USE$/) {
                    print $client "$code [$ecode] $msg\r\n";
                    $self->slog_("send: $code [$ecode] $msg");
                }
                elsif (defined $POP3_CAPA{"LOGIN-DELAY"} && $ecode =~ /^LOGIN\-DELAY$/) {
                    print $client "$code [$ecode] $msg\r\n";
                    $self->slog_("send: $code [$ecode] $msg");
                }
                elsif (defined $POP3_CAPA{"AUTH-RESP-CODE"} && $ecode =~ /^(SYS\/TEMP|SYS\/PERM|AUTH)$/) {
                    print $client "$code [$ecode] $msg\r\n";
                    $self->slog_("send: $code [$ecode] $msg");
                }
                else {
                    print $client "$code $msg\r\n";
                    $self->slog_("send: $code $msg");
                }
            }
            else {
                print $client "$code $msg\r\n";
                $self->slog_("send: $code $msg");
            }
        }
        else {
            print $client "$msg\r\n";
            $self->slog_("send: $msg");
        }
        alarm($self->{timeout});
    }
}



sub get_credentials {
    my ($self, $mech, $enc) = @_;
    my ($user, $pass, $other) = "";
    my $dec;

    (defined $mech && $mech) or return 0;
    (defined $enc && $enc) or return 0;
    # decode base64, but not for APOP or USER/PASS
    if ($mech ne "apop" && $mech ne "user" && $mech ne "pass") {
        $enc =~ s/([^\x2B-\x7A])//g;
        $enc =~ s/([\x2C-\x2E])//g;
        $enc =~ s/([\x3A-\x3C])//g;
        $enc =~ s/([\x3E-\x40])//g;
        $enc =~ s/([\x5B-\x60])//g;
        $dec = b64_dec($enc);
        (defined $dec && $dec) or return 0;
        $dec =~ s/[\r\n]*$//;
        $dec =~ s/[\s\t]{2,}/\ /g;
        $dec =~ s/^[\s\t]+//;
        ($dec) or return 0;
    }

    # USER/PASS: RFC 1939
    if ($mech eq "user" || $mech eq "pass") {
        $enc =~ s/[\r\n]*$//;
        $enc =~ s/[\s\t]{2,}/\ /g;
        $enc =~ s/^[\s\t]+//;
        $enc =~ s/[\s\t]+$//;
        # replace non-printable characters with "."
        $enc =~ s/([^\x20-\x7e])/\./g;
        if ($mech eq "user") {
            $user = $enc;
            $pass = "";
            (defined $user && $user) or return 0;
            (length($user) <= 1024) or return 0;
        }
        elsif ($mech eq "pass") {
            $user = "";
            $pass = $enc;
            (defined $pass && $pass) or return 0;
            (length($pass) <= 1024) or return 0;
        }
        $dec = $enc;
    }
    # APOP: RFC 1939
    if ($mech eq "apop") {
        $enc =~ s/[\r\n]*$//;
        $enc =~ s/[\s\t]{2,}/\ /g;
        $enc =~ s/^[\s\t]+//;
        $enc =~ s/[\s\t]+$//;
        # replace non-printable characters with "."
        $enc =~ s/([^\x20-\x7e])/\./g;
        ($user, $pass) = split(/\s+/, $enc, 2);
        # check user/digest
        (defined $user && $user && defined $pass && $pass) or return 0;
        $user =~ s/\s+$//;
        $pass =~ s/^\s+//;
        $pass =~ s/\s+$//;
        # check maximum length
        (length($user) <= 1024) or return 0;
        # check for valid md5
        ($pass =~ /^[[:xdigit:]]{32}$/) or return 0;
        $dec = $enc;
    }
    # ANONYMOUS: RFC 4505 [2245]
    elsif ($mech eq "anonymous") {
        $dec =~ s/[\s\t]+$//;
        # check maximum length
        (length($dec) <= 1024) or return 0;
        # replace non-printable characters with "."
        $dec =~ s/([^\x20-\x7e])/\./g;
        $user = $dec;
        $pass = "";
    }
    # PLAIN: RFC 4616 [2595]
    elsif ($mech eq "plain") {
        # check maximum length
        (length($dec) <= 1024) or return 0;
        ($other, $user, $pass) = split(/\x00/, $dec, 3);
        (defined $user && $user && defined $pass && $pass) or return 0;
        $other = "" if (! defined $other);
        $dec =~ s/[\x00]+/\ /g;
        $dec =~ s/^\s+//g;
        $other =~ s/^\s+//;
        $user =~ s/^\s+//;
        $user =~ s/\s+$//;
        $pass =~ s/^\s+//;
        # replace non-printable characters with "."
        $dec =~ s/([^\x20-\x7e])/\./g;
        $other =~ s/([^\x20-\x7e])/\./g;
        $user =~ s/([^\x20-\x7e])/\./g;
        $pass =~ s/([^\x20-\x7e])/\./g;
    }
    # LOGIN: http://tools.ietf.org/html/draft-murchison-sasl-login-00
    # check the username for login mechanism
    elsif ($mech eq "login_user") {
        $dec =~ s/[\s\t]+$//;
        # check maximum length
        (length($dec) < 64) or return 0;
        # replace non-printable characters with "."
        $dec =~ s/([^\x20-\x7e])/\./g;
        $user = $dec;
    }
    # check the password for login mechanism
    elsif ($mech eq "login_pass") {
        # check maximum length
        (length($dec) <= 1024) or return 0;
        # replace non-printable characters with "."
        $dec =~ s/([^\x20-\x7e])/\./g;
        $pass = $dec;
    }
    # CRAM-MD5/SHA1: RFC 2195
    elsif ($mech eq "cram-md5" || $mech eq "cram-sha1") {
        $dec =~ s/\s+$//;
        # replace non-printable characters with "."
        $dec =~ s/([^\x20-\x7e])/\./g;
        ($user, $pass) = split(/\s+/, $dec, 2);
        (defined $user && $user && defined $pass && $pass) or return 0;
        $user =~ s/\s+$//;
        $pass =~ s/^\s+//;
        $pass =~ s/\s+$//;
        # check maximum length
        (length($user) <= 1024) or return 0;
        # check for valid md5
        if ($mech eq "cram-md5" && $pass !~ /^[[:xdigit:]]{32}$/) {
            return 0;
        }
        # check for valid sha1
        if ($mech eq "cram-sha1" && $pass !~ /^[[:xdigit:]]{40}$/) {
            return 0;
        }
    }

    return ($dec, $user, $pass, $other);
}



sub AUTH {
    my ($self, $args) = @_;
    my $client = $self->{server}->{client};
    my @methods = split(/[\s\t]+/, $POP3_CAPA{SASL});
    my ($encoded, $decoded);
    my ($user, $pass, $other, $dummy);

    if ($self->{state} ne "auth") {
        $self->send_("-ERR", "Command not available in TRANSACTION state.");
        return;
    }
    if (! defined $args || $args eq "" || $args =~ /^[\s\t]+\z/) {
        $self->send_("+OK", "List of supported authentication methods follows");
        foreach (@methods) {
            $self->send_("", "$_");
        }
        $self->send_("", ".");
        return;
    }
    my ($mechanism, $string, $more) = split(/[\s\t]+/, $args, 3);
    if (defined $more && $more && $more !~ /^[\s\t]+\z/) {
        $self->send_("-ERR", "Too many arguments for the auth command.");
        return;	
    }
    if (! defined $mechanism || ! $mechanism) {
        $self->send_("-ERR", "Too few arguments for the auth command.");
        return;	
    }
    if ($mechanism !~ /^(ANONYMOUS|PLAIN|LOGIN|CRAM-MD5|CRAM-SHA1)$/i) {
        $self->send_("-ERR", "Unknown authentication method");
        return;
    }
    $mechanism = lc($mechanism);
    # test for allowed methods
    my $found = 0;
    foreach (@methods) {
        if ($mechanism eq lc($_)) {
            $found = 1;
            last;
        }
    }
    if (! $found) {
        $self->send_("-ERR", "Unknown authentication method");
        return;
    }

    ### ANONYMOUS or PLAIN
    if ($mechanism eq "anonymous" || $mechanism eq "plain") {
        if (! defined $string || $string eq "") {
            $self->send_("", "+ Go on");
            alarm($self->{timeout});
            chomp($string = <$client>);
            alarm($self->{timeout});
            $string =~ s/\r$//g;
            $string =~ s/[\r\n]+//g;
            # replace non-printable characters with "."
            $string =~ s/([^\x20-\x7e])/\./g;
            $self->slog_("recv: $string");
        }
        if (! defined $string || $string eq "") {
            $self->send_("-ERR", "Authentication failed.", "AUTH");
            return;
        }
        if ($string =~ /^\*/) {
            $self->send_("-ERR", "Authentication cancelled");
            return;
        }
        ($decoded, $user, $pass, $other) = $self->get_credentials($mechanism, $string);
        if (! defined $decoded || ! $decoded) {
            $self->send_("-ERR", "Authentication failed.", "AUTH");
            return;
        }
        $self->slog_("info: $string  -->  $decoded");
    }
    ### LOGIN
    elsif ($mechanism eq "login") {
        if (defined $string && $string eq "") {
            $self->send_("-ERR", "Authentication failed.", "AUTH");
            return;
        }
        # ask for username
        $self->send_("", "+ VXNlcm5hbWU6");
        $self->slog_("info: VXNlcm5hbWU6  -->  Username:");
        alarm($self->{timeout});
        chomp($string = <$client>);
        alarm($self->{timeout});
        $string =~ s/\r$//g;
        $string =~ s/[\r\n]+//g;
        # replace non-printable characters with "."
        $string =~ s/([^\x20-\x7e])/\./g;
        $self->slog_("recv: $string");
        if (! defined $string || $string eq "") {
            $self->send_("-ERR", "Authentication failed.", "AUTH");
            return;
        }
        if ($string =~ /^\*/) {
            $self->send_("-ERR", "Authentication cancelled");
            return;
        }
        ($decoded, $user, $dummy, $other) = $self->get_credentials("login_user", $string);
        if (! defined $decoded || ! $decoded) {
            $self->send_("-ERR", "Authentication failed.", "AUTH");
            return;
        }
        $self->slog_("info: $string  -->  $decoded");
        # ask for password
        $self->send_("", "+ UGFzc3dvcmQ6");
        $self->slog_("info: UGFzc3dvcmQ6  -->  Password:");
        alarm($self->{timeout});
        chomp($string = <$client>);
        alarm($self->{timeout});
        $string =~ s/\r$//g;
        $string =~ s/[\r\n]+//g;
        # replace non-printable characters with "."
        $string =~ s/([^\x20-\x7e])/\./g;
        $self->slog_("recv: $string");
        if (! defined $string || $string eq "") {
            $self->send_("-ERR", "Authentication failed.", "AUTH");
            return;
        }
        if ($string =~ /^\*/) {
            $self->send_("-ERR", "Authentication cancelled");
            return;
        }
        ($decoded, $dummy, $pass, $other) = $self->get_credentials("login_pass", $string);
        if (! defined $decoded || ! $decoded) {
            $self->send_("-ERR", "Authentication failed.", "AUTH");
            return;
        }
        $self->slog_("info: $string  -->  $decoded");
    }
    ### CRAM-MD5 or CRAM-SHA1
    elsif ($mechanism eq "cram-md5" || $mechanism eq "cram-sha1") {
        if (defined $string && $string eq "") {
            $self->send_("-ERR", "Authentication failed.", "AUTH");
            return;
        }
        my $greeting = "<$$." . &INetSim::FakeTime::get_faketime() . '@' . "$self->{hostname}>";
        $encoded = encode_base64($greeting);
        $encoded =~ s/[\r\n]+$//;
        $self->send_("", "+ $encoded");
        $self->slog_("info: $encoded  -->  $greeting");
        alarm($self->{timeout});
        chomp($string = <$client>);
        alarm($self->{timeout});
        $string =~ s/\r$//g;
        $string =~ s/[\r\n]+//g;
        # replace non-printable characters with "."
        $string =~ s/([^\x20-\x7e])/\./g;
        $self->slog_("recv: $string");
        if (! defined $string || $string eq "") {
            $self->send_("-ERR", "Authentication failed.", "AUTH");
            return;
        }
        if ($string =~ /^\*/) {
            $self->send_("-ERR", "Authentication cancelled");
            return;
        }
        ($decoded, $user, $pass, $other) = $self->get_credentials($mechanism, $string);
        if (! defined $decoded || ! $decoded) {
            $self->send_("-ERR", "Authentication failed.", "AUTH");
            return;
        }
        $self->slog_("info: $string  -->  $decoded");
    }

    ### Authentication successful...
    if (! $self->session_lock("lock")) {
        $self->send_("-ERR", "maildrop already locked.", "IN-USE");
        $self->{lock_error} = 1;
        $self->{close_connection} = 1;
        return;
    }

    if ($self->login_delay()) {
        $self->send_("-ERR", "minimum time between mail checks violation", "LOGIN-DELAY");
        $self->{close_connection} = 1;
        return;
    }

    $status{success} = 1;
    $status{auth_type} = "sasl/$mechanism";
    $status{credentials} = "$user:$pass";

    $self->{state} = "trans";

    $self->mbox_reread();
    $self->mbox_rebuild();
    $self->session_read();

    $self->spoolinfo();
}



sub USER {
    my ($self, $args) = @_;
    my ($user, $pass, $other, $dummy);

    if ($self->{state} ne "auth") {
        $self->send_("-ERR", "Command not available in TRANSACTION state.");
        return;
    }
    if (! defined $args || ! $args || $args =~ /^[\s\t]+\z/) {
        $self->send_("-ERR", "Too few arguments for the user command.");
        return;
    }
    ($dummy, $user, $pass, $other) = $self->get_credentials("user", $args);
    if (! defined $dummy || ! $dummy) {
        $self->send_("-ERR", "Wrong username.");
        return;
    }
    if (length($user) < 2) {
        $self->send_("-ERR", "No such user.", "SYS/TEMP");
        return;
    }
    if (length($user) > 508) {
        $self->send_("-ERR", "Username too long.", "SYS/PERM");
        return;
    }

    $status{auth_type} = "user/pass";

    $self->{state} = "auth";
    $self->{username} = $user;
    $self->send_("+OK", "Please give password.");
}



sub PASS {
    my ($self, $args) = @_;
    my ($user, $pass, $other, $dummy);

    if ($self->{state} ne "auth") {
        $self->send_("-ERR", "Command not available in TRANSACTION state.");
        return;
    }
    if (! defined $self->{username} || ! $self->{username}) {
        $self->send_("-ERR", "Please give username first.");
        return;
    }
    if (! defined $args || ! $args || $args =~ /^[\s\t]+\z/) {
        $self->send_("-ERR", "Too few arguments for the pass command.");
        return;
    }
    ($dummy, $user, $pass, $other) = $self->get_credentials("pass", $args);
    if (! defined $dummy || ! $dummy) {
        $self->send_("-ERR", "Authentication failed.", "AUTH");
        return;
    }
    if (length($pass) < 2) {
        $self->send_("-ERR", "Wrong password.", "AUTH");
        return;
    }
    if (length($pass) > 508) {
        $self->send_("-ERR", "Password too long", "SYS/PERM");
        return;
    }

    if (! $self->session_lock("lock")) {
        $self->send_("-ERR", "maildrop already locked.", "IN-USE");
        $self->{lock_error} = 1;
        $self->{close_connection} = 1;
        return;
    }

    if ($self->login_delay()) {
        $self->send_("-ERR", "minimum time between mail checks violation", "LOGIN-DELAY");
        $self->{close_connection} = 1;
        return;
    }

    $status{success} = 1;
    $status{auth_type} = "user/pass";
    $status{credentials} = "$self->{username}:$pass";

    $self->{state} = "trans";

    $self->mbox_reread();
    $self->mbox_rebuild();
    $self->session_read();

    $self->spoolinfo();
}



sub APOP {
    my ($self, $args) = @_;
    my ($user, $digest, $other, $dummy);

    if ($self->{state} ne "auth") {
        $self->send_("-ERR", "Command not available in TRANSACTION state.");
        return;
    }
    if (! defined $args || $args eq "" || $args =~ /^[\s\t]+\z/) {
        $self->send_("-ERR", "Too few arguments for the apop command.");
        return;
    }
    ($dummy, $user, $digest, $other) = $self->get_credentials("apop", $args);
    if (! defined $dummy || ! $dummy) {
        $self->send_("-ERR", "Authentication failed.", "AUTH");
        return;
    }
    if (length($user) < 2) {
        $self->send_("-ERR", "No such user.", "SYS/TEMP");
        return;
    }
    if (length($user) > 476) {
        $self->send_("-ERR", "Username too long.", "SYS/PERM");
        return;
    }

    if (! $self->session_lock("lock")) {
        $self->send_("-ERR", "Maildrop already locked.", "IN-USE");
        $self->{lock_error} = 1;
        $self->{close_connection} = 1;
        return;
    }

    if ($self->login_delay()) {
        $self->send_("-ERR", "minimum time between mail checks violation", "LOGIN-DELAY");
        $self->{close_connection} = 1;
        return;
    }

    $status{success} = 1;
    $status{auth_type} = "apop";
    $status{credentials} = "$user:$digest";

    $self->{state} = "trans";

    $self->mbox_reread();
    $self->mbox_rebuild();
    $self->session_read();

    $self->spoolinfo();
}



sub QUIT {
    my ($self, $args) = @_;

    if (defined $args && $args && $args !~ /^[\s\t]+\z/) {
        $self->send_("-ERR", "Too many arguments for the quit command.");
        return;
    }
    if ($self->{state} eq "trans") {
        $self->{state} = "update";
        $self->session_update();
        $self->session_lock("unlock");
    }
    $self->{state} = "auth";
    $self->{close_connection} = 1;
    $self->send_("+OK", "Bye.");
}



sub CAPA {
    my ($self, $args) = @_;

    if (defined $args && $args && $args !~ /^[\s\t]+\z/) {
        $self->send_("-ERR", "Too many arguments for the capa command.");
        return;
    }
    # do multiline output
    $self->send_("+OK", "Capability list follows");
    foreach (keys %POP3_CAPA) {
        if ($POP3_CAPA{$_} ne "") {
            $self->send_("", "$_ $POP3_CAPA{$_}");
        }
        else {
            $self->send_("", "$_");
        }
    }
    $self->send_("", ".");
}



sub STAT {
    my ($self, $args) = @_;

    if ($self->{state} ne "trans") {
        $self->send_("-ERR", "Unknown command.");
        return;
    }
    if (defined $args && $args && $args !~ /^[\s\t]+\z/) {
        $self->send_("-ERR", "Too many arguments for the stat command.");
        return;
    }
    $self->spoolinfo("STAT");
}



sub LIST {
    my ($self, $args) = @_;
    my $client = $self->{server}->{client};

    if ($self->{state} ne "trans") {
        $self->send_("-ERR", "Unknown command.");
        return;
    }
    if (defined $args && $args) {
        $args =~ s/^[\s\t]+//;
        $args =~ s/[\s\t]+\z//;
        if (! $args || $args !~ /^\d+\z/) {
            $self->send_("-ERR", "Invalid message number.");
            return;
        }
        my ($flag, $hash, $uid, $size, $header, $body) = $self->read_mail($args);
        if (defined $flag && $flag) {
            $self->send_("+OK", "$args $size");
        }
        else {
            $self->send_("-ERR", "No such message or message deleted.");
            return;
        }
    }
    else {
        $self->spoolinfo("LIST");
    }
}



sub RETR {
    my ($self, $args) = @_;
    my $client = $self->{server}->{client};

    if ($self->{state} ne "trans") {
        $self->send_("-ERR", "Unknown command.");
        return;
    }
    if (! defined $args || ! $args) {
        $self->send_("-ERR", "Too few arguments for the retr command.");
        return;
    }
    $args =~ s/^[\s\t]+//;
    $args =~ s/[\s\t]+\z//;
    if (! $args || $args !~ /^\d+\z/) {
        $self->send_("-ERR", "Invalid message number.");
        return;
    }
    my ($flag, $hash, $uid, $size, $header, $body) = $self->read_mail($args);
    if (defined $flag && $flag) {
        $self->send_("+OK", "Message follows ($size octets)");
        print $client "$header\r\n$body";
        $self->slog_("send: <(MESSAGE)>");
        print $client "\r\n.\r\n";
        $self->slog_("send: .");
        $status{retrieved}++;
    }
    else {
        $self->send_("-ERR", "No such message or message deleted.");
    }
}



sub DELE {
    my ($self, $args) = @_;

    if ($self->{state} ne "trans") {
        $self->send_("-ERR", "Unknown command.");
        return;
    }
    if (! defined $args || ! $args) {
        $self->send_("-ERR", "Too few arguments for the dele command.");
        return;
    }
    $args =~ s/^[\s\t]+//;
    $args =~ s/[\s\t]+\z//;
    if (! $args || $args !~ /^\d+\z/) {
        $self->send_("-ERR", "Invalid message number.");
        return;
    }
    if ($self->mark_mail($args)) {
        $self->send_("+OK", "Message deleted");
        $status{deleted}++;
    }
    else {
        $self->send_("-ERR", "No such message");
    }
}



sub TOP {
    my ($self, $args) = @_;
    my $client = $self->{server}->{client};

    if ($self->{state} ne "trans") {
        $self->send_("-ERR", "Unknown command.");
        return;
    }
    if (! defined $args || $args eq "" || $args =~ /^[\s\t]+\z/) {
        $self->send_("-ERR", "Too few arguments for the top command.");
        return;
    }
    my ($number, $lines, $more) = split(/[\s\t]+/, $args, 3);
    if (defined $more && $more && $more !~ /^[\s\t]+\z/) {
        $self->send_("-ERR", "Too many arguments for the top command.");
        return;	
    }
    if (! $number || $number !~ /^\d+\z/) {
        $self->send_("-ERR", "Invalid message number.");
        return;
    }
    if (! defined $lines || $lines !~ /^\d+\z/) {
        $self->send_("-ERR", "Invalid number of lines.");
        return;
    }
    my ($flag, $hash, $uid, $size, $header, $body) = $self->read_mail($number);
    if (defined $flag && $flag) {
        my @out = split (/\r\n/, $body);
        $self->send_("+OK", "top of message follows");
        print $client "$header\r\n";
        $self->slog_("send: <(MESSAGEPART)>");
        if ($lines) {
            my $i = 0;
            foreach (@out) {
                print $client $out[$i];
                $i++;
                last if ($i >= $lines);
                print $client "\r\n";
            }
        }
        print $client "\r\n.\r\n";
        $self->slog_("send: .");
    }
    else {
        $self->send_("-ERR", "No such message or message deleted.");
    }
}



sub UIDL {
    my ($self, $args) = @_;
    my $client = $self->{server}->{client};

    if ($self->{state} ne "trans") {
        $self->send_("-ERR", "Unknown command.");
        return;
    }
    if (defined $args && $args) {
        $args =~ s/^[\s\t]+//;
        $args =~ s/[\s\t]+\z//;
        if (! $args || $args !~ /^\d+\z/) {
            $self->send_("-ERR", "Invalid message number.");
            return;
        }
        my ($flag, $hash, $uid, $size, $header, $body) = $self->read_mail($args);
        if (defined $flag && $flag) {
            $self->send_("+OK", "$args $uid");
        }
        else {
            $self->send_("-ERR", "No such message or message deleted.");
            return;
        }
    }
    else {
        $self->spoolinfo("UIDL");
    }
}



sub NOOP {
    my ($self, $args) = @_;

    if ($self->{state} ne "trans") {
        $self->send_("-ERR", "Unknown command.");
        return;
    }
    if (defined $args && $args && $args !~ /^[\s\t]+\z/) {
        $self->send_("-ERR", "Too many arguments for the noop command.");
        return;
    }
    $self->send_("+OK", "");
}



sub RSET {
    my ($self, $args) = @_;

    if ($self->{state} ne "trans") {
        $self->send_("-ERR", "Unknown command.");
        return;
    }
    if (defined $args && $args && $args !~ /^[\s\t]+\z/) {
        $self->send_("-ERR", "Too many arguments for the rset command.");
        return;
    }
    $self->spoolinfo();
}



sub STLS {
    my ($self, $args) = @_;

    if (defined $args && $args && $args !~ /^[\s\t]+\z/) {
        $self->send_("-ERR", "Too many arguments for the stls command.");
        return;
    }
    if ($self->{using_tls}) {
        $self->send_("-ERR", "Command not permitted when TLS active");
        return;
    }
    if ($self->{state} ne "auth") {
        $self->send_("-ERR", "Command not available in TRANSACTION state.");
        return;
    }
    $self->send_("+OK", "Begin TLS negotiation");
    if ($self->upgrade_to_ssl()) {
        # deleting STLS extension (rfc 2595, section 4)
        delete $POP3_CAPA{"STLS"};
        # set tls flag
        $self->{using_tls} = 1;
        $status{tls_used} = 1;
        # log success
        $self->slog_("info: Connection successfully upgraded to SSL");
    }
    else {
        $self->slog_("info: Upgrade to SSL failed:  $self->{last_ssl_error}");
        $self->{close_connection} = 1;
    }
}



sub login_delay {
    my $self = shift;
    my $now = &INetSim::FakeTime::get_faketime();

    $self->last_login();
    if ($self->{capabilities} && defined $POP3_CAPA{"LOGIN-DELAY"} && $POP3_CAPA{"LOGIN-DELAY"} =~ /^(\d+)(\sUSER)?$/) {
        my $diff = &timediff($now, $self->{last_login});
        if ($1 && $diff <= $1) {
            return 1;
        }
    }
    $self->{last_login} = $now;

    return 0;
}



sub spoolinfo {
    my ($self, $args) = @_;
    my $client = $self->{server}->{client};
    my $count_all = 0;
    my $size_all = 0;
    my $i;
    my @uid;
    my @lst;

    for ($i = 1; $i < scalar @MBOX; $i++) {
        my ($flag, $hash, $uid, $size, $header, $body) = $self->read_mail($i);
        if (defined $flag && $flag) {
            $count_all++;
            $size_all += $size;
            push (@uid, "$i $uid");
            push (@lst, "$i $size");
        }
    }

    if (! defined $args || ! $args) {
        $self->send_("+OK", "$count_all message(s) ($size_all octets).");
        return;
    }
    # extra stuff required by other commands
    if ($args eq "UIDL") {
        $self->send_("+OK", "UID listing follows");
        foreach (@uid) {
            print $client "$_\r\n";
        }
        $self->slog_("send: <(MESSAGEUIDS)>");
        $self->send_("", ".");
    }
    elsif ($args eq "LIST") {
        $self->send_("+OK", "$count_all message(s) ($size_all octets).");
        foreach (@lst) {
            print $client "$_\r\n";
        }
        $self->slog_("send: <(MESSAGELIST)>");
        $self->send_("", ".");
    }
    elsif ($args eq "STAT") {
        $self->send_("+OK", "$count_all $size_all");
    }
}



sub add_mail {
    my ($self, $msg) = @_;
    my ($flag, $hash, $uid, $size, $header, $body);

    (defined $msg && $msg) or return 0;
    # remove mbox 'From '
    $msg =~ s/^From .*?[\r\n]+//;
    # convert LF to CR/LF
    $msg =~ s/\r\n/\n/g;
    $msg =~ s/\n/\r\n/g;
    # quote 'CR+LF+.+CR+LF'
    $msg =~ s/\r\n\.\r\n/\r\n\.\.\r\n/g;
    # split header & body
    $msg =~ s/(\r\n){2,}/\|/;
    ($header, $body) = split(/\|/, $msg, 2);
    $header =~ s/[\r\n]+$//;
    $header =~ s/^[\r\n]+//;
    $body =~ s/[\r\n]+$//;
    $body =~ s/^[\r\n]+//;
    $header .= "\r\n";
    $body .= "\r\n";
    # get message length
    $size = int(length($header . $body) + 2);
    # hash the first 1024 bytes
    my $sha1 = Digest::SHA->new;
    $sha1->add(substr($msg, 0, 1024));
    $hash = lc($sha1->hexdigest);
    # use 16 chars from hash as message uid
    $uid = substr($hash, 0, 16);
    # set flag (0 = deleted, 1 = available)
    $flag = 1;
    # add infos and the message to the array
    push (@MBOX, "$flag|$hash|$uid|$size|$header|$body");
    return 1;
}



sub read_mail {
    my ($self, $number) = @_;
    my ($flag, $hash, $uid, $size, $header, $body);

    (defined $number && $number) or return 0;
    (defined $MBOX[$number]) or return 0;
    ($flag, $hash, $uid, $size, $header, $body) = split(/\|/, $MBOX[$number], 6);
    return ($flag, $hash, $uid, $size, $header, $body);
}



sub mark_mail {
    my ($self, $number) = @_;

    (defined $number && $number) or return 0;
    (defined $MBOX[$number]) or return 0;
    ($MBOX[$number] =~ /^1/) or return 0;
    $MBOX[$number] =~ s/^1(.*)$/0$1/m;
    return 1;
}



sub unmark_mail {
    my ($self, $number) = @_;

    (defined $number && $number) or return 0;
    (defined $MBOX[$number]) or return 0;
    ($MBOX[$number] =~ /^0/) or return 0;
    $MBOX[$number] =~ s/^0(.*)$/1$1/m;
    return 1;
}



sub mbox_reread {
    my $self = shift;
    my $mboxdirname = $self->{mboxdirname};
    my $now = &INetSim::FakeTime::get_faketime();
    my $last = $self->last_filechange($self->{datfile});
    my $diff = &timediff($now, $last);

    if ($diff && $diff > $self->{mbox_reread}) {
        my @files;
        chomp(@files = <${mboxdirname}/*.mbox>);
	if (@files) {
	    if (! open (DAT, ">$self->{datfile}")) {
	        $self->dlog_("Could not open data file: $!");
		return 0;
	    }
	    print DAT "CreationTime: $now\n";
	    my $file;
	    foreach $file (@files) {
	        if (! open (MBX, "$file")) {
		    $self->dlog_("Could not open mbox file: $!");
		    next;
		}
		while (<MBX>) {
		    s/\r\n/\n/g;
		    print DAT $_;
		}
		print DAT "\n";
		close MBX;
	    }
	    close DAT;
	}
	return 1;
    }
    return 0;
}



sub mbox_rebuild {
    my $self = shift;
    my $now = &INetSim::FakeTime::get_faketime();
    my $last = $self->last_filechange($self->{sessiondatfile});
    my $diff = &timediff($now, $last);
    my $max_mails = int(rand($self->{mbox_maxmails}));

    if ($diff && $diff > $self->{mbox_rebuild}) {
        if (! open (SES, ">$self->{sessiondatfile}")) {
	    $self->dlog_("Could not open sessiondata file: $!");
	    return 0;
	}
	print SES "CreationTime: $now\n";
	print SES "LastLogin: $self->{last_login}\n";
	if (! open (DAT, "$self->{datfile}")) {
	    $self->dlog_("Could not open data file: $!");
	    close SES;
	    return 0;
	}
	my $msg;
	my $count = 0;
	my $line;
	my $last = "";
	while ($line = <DAT>) {
	    $line =~ s/\r\n/\n/g;
	    next if ($line =~ /^CreationTime: (\d+)?$/);
	    if ($line =~ /^From /) {
	        if (defined $msg && $msg && $msg =~ /^From / && int(rand(100)) % 2 && $count < $max_mails) {
	            print SES "$msg\n";
	            $count++;
	            $last = "";
		}
                $msg = undef;
	    }
	    $msg .= $line;
	    last if ($count >= $max_mails);
	    $last = $line;
	}
	close DAT;
	close SES;
	return 1;
    }
    return 0;
}



sub session_read {
    my $self = shift;
    my $count = 0;
    my $line;
    my $last = "";
    my $msg;

    if (! open (SES, "$self->{sessiondatfile}")) {
        $self->dlog_("Could not open session data file: $!");
        return 0;
    }
    while ($line = <SES>) {
        next if ($line =~ /^CreationTime: (\d+)?$/);
        next if ($line =~ /^LastLogin: (\d+)?$/);
        if (defined $msg && $msg && $line =~ /^From / && $last =~ /^$/) {
                $self->add_mail($msg);
                $count++;
                $msg = undef;
        }
        $msg .= $line;
    }
    if (defined $msg && $msg && $msg =~ /^From /) {
        $self->add_mail($msg);
        $count++;
    }
}



sub session_update {
    my $self = shift;
    my $now = &INetSim::FakeTime::get_faketime();

    if (! open (SES, ">$self->{sessiondatfile}")) {
        $self->dlog_("Could not open session data file: $!");
        return 0;
    }
    print SES "CreationTime: $now\n";
    print SES "LastLogin: $self->{last_login}\n";
    my $i;
    for ($i = 1; $i < scalar @MBOX; $i++) {
        my ($flag, $hash, $uid, $size, $header, $body) = $self->read_mail($i);
        if (defined $flag && $flag) {
            print SES "From unknown\n";
            print SES "$header\n$body\n\n";
        }
    }
    close SES;
}



sub session_lock {
    my $self = shift;
    my $cmd = shift || "status";
    my $lock = 0;

    if (open(LCK, "<$self->{sessionlockfile}")) {
        $lock = <LCK>;
        close LCK;
    }
    else {
        $self->dlog_("Could not open lock file: $!");
        return 0;
    }
    if ($cmd eq "lock") {
        # already locked
        return 0 if ($lock);
        $lock = &INetSim::FakeTime::get_faketime();
        if (open(LCK, ">$self->{sessionlockfile}")) {
            print LCK $lock;
            close LCK;
            return $lock;
        }
        else {
            $self->dlog_("Could not open lock file: $!");
            return 0;
        }
    }
    elsif ($cmd eq "unlock") {
        # not locked
        return 0 if (! $lock);
        $lock = 0;
        if (open(LCK, ">$self->{sessionlockfile}")) {
            print LCK $lock;
            close LCK;
            return $lock;
        }
        else {
            $self->dlog_("Could not open lock file: $!");
            return 0;
        }
    }
    else {
        return $lock;
    }
}



sub timediff {
    my ($time1, $time2) = @_;
    my $diff = 0;

    if (defined $time1 && defined $time2) {
        if ($time1 > $time2) {
            $diff = $time1 - $time2;
        }
        elsif ($time2 > $time1) {
            $diff = $time2 - $time1;
        }
        else {
            $diff = 0;
        }
    }
    return $diff;
}



sub last_filechange {
    my ($self, $file) = @_;

    (defined $file && $file && -f $file) or return 0;

    if (! open (FILE, "$file")) {
        $self->dlog_("Could not open file '$file': $!");
        return 0;
    }
    my $ts = <FILE>;
    close FILE;
    if (defined $ts && $ts && $ts =~ /^CreationTime:\s(\d+)$/) {
        (defined $1 && $1) and return $1;
    }
    return 1;
}



sub last_login {
    my $self = shift;

    if (! open (SES, "$self->{sessiondatfile}")) {
        $self->dlog_("Could not open session data file: $!");
        return 0;
    }
    my $dummy = <SES>;
    my $last = <SES>;
    close SES;
    if (defined $last && $last && $last =~ /^LastLogin:\s(\d+)$/) {
        $self->{last_login} = $1;
    }
    else {
        $self->{last_login} = 0;
    }

    return 1;
}



sub b64_dec {
    my $string = shift;
    my $length;
    my $out;

    (defined $string && $string) or return 0;
    (length($string) % 4 == 0) or return 0;
    ($string =~ /^[A-Za-z0-9\+\/]+([\=]{0,2})$/) or return 0;

    return decode_base64($string);
}



sub register_capabilities {
    my $self = shift;
    my %conf_capa;

    if ($self->{capabilities}) {
        if ($self->{ssl_enabled}) {
            %conf_capa = &INetSim::Config::getConfigHash("POP3S_Capabilities");
        }
        else {
            %conf_capa = &INetSim::Config::getConfigHash("POP3_Capabilities");
        }
        foreach (keys %conf_capa) {
            if (defined ($CAPA_AVAIL{$_}) && $CAPA_AVAIL{$_}) {
                if (! defined ($POP3_CAPA{$_})) {
                    # for compatibility with old option 'pop3_auth_reversibleonly'
                    if ($_ eq "SASL" && $self->{auth_reversible_only}) {
                        $conf_capa{$_} =~ s/CRAM-(MD5|SHA1)([\s]+)?//g;
                        # do not register without any mechanism
                        next if ($conf_capa{$_} !~ /[A-Za-z0-9]+/);
                    }
                    $conf_capa{$_} =~ s/[\s]+$//;
                    # parameters are allowed
                    if ($CAPA_AVAIL{$_} == 2) {
                        $POP3_CAPA{$_} = $conf_capa{$_};
                    }
                    # parameters are not allowed
                    else {
                        $POP3_CAPA{$_} = "";
                    }
                }
            }
        }
        # resolve possible dependencies below...
        #
        # disable SASL, if no mechanisms are set
        if (defined $POP3_CAPA{SASL} && $POP3_CAPA{SASL} eq "") {
            delete $POP3_CAPA{SASL};
        }
        # disable STLS, if SSL library not found or certfile/keyfile not found/not readable/empty
        if (! $SSL || ! -f $self->{ssl_key} || ! -r $self->{ssl_key} || ! -f $self->{ssl_crt} || ! -r $self->{ssl_crt} || ! -s $self->{ssl_key} || ! -s $self->{ssl_crt}) {
            delete $POP3_CAPA{STLS};
        }
        # warn about missing dh file and disable
        if (defined $self->{ssl_dh} && (! -f $self->{ssl_dh} || ! -r $self->{ssl_dh} || ! -s $self->{ssl_dh})) {
            &INetSim::Log::MainLog("Warning: Unable to read Diffie-Hellman parameter file '$self->{ssl_dh}'", $self->{servicename});
            $self->{ssl_dh} = undef;
        }
        # disable STLS, if already using SSL
        if ($self->{ssl_enabled}) {
            delete $POP3_CAPA{STLS};
        }
        # check LOGIN-DELAY
        if (defined $POP3_CAPA{"LOGIN-DELAY"} && $POP3_CAPA{"LOGIN-DELAY"} !~ /^\d+(\sUSER)?$/) {
            delete $POP3_CAPA{"LOGIN-DELAY"};
        }
        # check EXPIRE
        if (defined $POP3_CAPA{EXPIRE} && $POP3_CAPA{EXPIRE} !~ /^(\d+|NEVER|\d+\sUSER)$/) {
            delete $POP3_CAPA{EXPIRE};
        }
        # check IMPLEMENTATION
        if (defined $POP3_CAPA{IMPLEMENTATION} && $POP3_CAPA{IMPLEMENTATION} eq "") {
            $POP3_CAPA{IMPLEMENTATION} = $self->{version};
        }
    }

    # if USER and SASL capabilities and the APOP command are disabled, enable the weakest authentication mechanism (USER/PASS)
    if (! defined $POP3_CAPA{USER} && ! defined $POP3_CAPA{SASL} && ! $self->{enable_apop}) {
        $POP3_CAPA{USER} = "";
    }
}



sub upgrade_to_ssl {
    my $self = shift;
    my %ssl_params = (	SSL_version             => "SSLv23",
			SSL_cipher_list		=> "ALL",
			SSL_server              => 1,
			SSL_use_cert            => 1,
			SSL_key_file            => $self->{ssl_key},
			SSL_cert_file           => $self->{ssl_crt} );

    $self->{last_ssl_error} = "";

    if (defined $self->{ssl_dh} && $self->{ssl_dh}) {
        $ssl_params{'SSL_dh_file'} = $self->{ssl_dh};
    }

    my $result = IO::Socket::SSL::socket_to_SSL( $self->{server}->{client}, %ssl_params );

    if (defined $result) {
        $status{tls_cipher} = lc($result->get_cipher());
        return 1;
    }
    else {
        $self->{last_ssl_error} = IO::Socket::SSL::errstr();
        return 0;
    }
}



sub error_exit {
    my ($self, $msg) = @_;
    my $rhost = $self->{server}->{peeraddr};
    my $rport = $self->{server}->{peerport};

    if (! defined $msg) {
        $msg = "Unknown error";
    }
    &INetSim::Log::MainLog("$msg. Closing connection.", $self->{servicename});
    &INetSim::Log::SubLog("[$rhost:$rport] error: $msg. Closing connection.", $self->{servicename}, $$);
    &INetSim::Log::SubLog("[$rhost:$rport] disconnect", $self->{servicename}, $$);
    exit 1;
}



1;
#############################################################
#
# History:
#
# Version 0.106  (2014-05-23) th
# - changed SSL_version to "SSLv23"
#
# Version 0.105  (2010-06-16) me
# - fixed a small typo - THX to Stephan N.
#
# Version 0.104  (2010-04-12) me
# - do not filter non-printable characters because it's already
#   implemented in the log module
#
# Version 0.103  (2009-12-19) me
# - added new configuration variable 'CertDir'
#
# Version 0.102  (2009-10-09) me
# - added generic function spoolinfo() to get some informations
#   about the messages in one step
# - added generic decoder/parser function get_credentials() and
#   fixed some bugs in the authentication part - i believe, it
#   should be bullet-proof now :-)
# - fixed small typos
#
# Version 0.101  (2009-10-06) me
# - fixed small typo in function AUTH
# - added new optional config paramter 'POP3[S]_DHFileName'
# - changed function upgrade_to_ssl() to work with Diffie-Hellman
#   parameters and added 'ALL' available ciphers to the SSL
#   options (except 'eNULL')
# - added information about TLS and SSL cipher to the status line
#
# Version 0.100  (2009-09-25) me
# - added check for SSL library and cert files
# - added new config parameter 'POP3[S]_Version'
#
# Version 0.99   (2009-09-24) me
# - fixed small typo
#
# Version 0.98   (2009-09-23) me
# - changed logging for TOP command
# - added regular POP3 error response for session timeout
#
# Version 0.97   (2009-09-22) me
# - enhanced support for LOGIN-DELAY, RESP-CODES and AUTH-RESP-CODE
# - added more checks to register_capabilities()
# - fixed some bugs in mbox_rebuild()
#
# Version 0.96   (2009-09-10) me
# - added function register_capabilities()
# - changed handling of mbox files
# - changed handling of session data
# - substituted message for maximum connections with an regular POP3
#   error response
# - added quoting for '.' in mail body
# - added support for TOP (RFC 2449)
# - added support for STLS (RFC 2595)
#
# Version 0.95   (2009-09-07) me
# - complete rewrite (oo-style)
# - added generic function send_()
# - changed regular expression for commands
# - added new ConfigParameter 'POP3[S]_EnableAPOP'
# - changed server greeting, because it depends on APOP support
#   (for details see RFC 2449, section 6.0)
# - added support for IMPLEMENTATION (RFC 1939, 2449)
# - added support for LOGIN-DELAY and EXPIRE (RFC 2449)
# - added support for RESP-CODES and AUTH-RESP-CODE (RFC 2449, 3206)
# - added support for authentication mechanisms ANONYMOUS and CRAM-SHA1
#
# Version 0.94   (2009-09-04) me
# - prepared for complete rewrite ;-)
# - added hash for available capabilities
# - added support for SSL (pop3s)
# - added generic functions slog_(), dlog_() and upgrade_to_ssl()
# - some bugfixes with variables
# - removed a bunch of unnecessary variables
#
# Version 0.93   (2009-08-27) me
# - replace non-printable characters with "."
#
# Version 0.92   (2008-08-27) me
# - added logging of process id
#
# Version 0.91   (2008-06-26) me
# - fixed problem with uninitialized variables
#
# Version 0.90   (2008-03-25) me
# - changed timeout handling
#
# Version 0.89   (2008-03-19) me
# - added timeout after inactivity of n seconds, using new
#   config parameter Default_TimeOut
#
# Version 0.88  (2007-12-31) th
# - change process name
#
# Version 0.87  (2007-12-09) me
# - changed authentication mechanism support for use with new
#   ConfigParameter "POP3_AuthReversibleOnly"
#
# Version 0.86  (2007-10-21) th
# - added "/" to beginning of filenames in POP3_MBOXDirName
#
# Version 0.85  (2007-10-20) me
# - added new ConfigParameter "POP3_MBOXMaxMails"
# - added new ConfigParameter "POP3_MBOXReRead"
# - added new ConfigParameter "POP3_MBOXReBuild"
# - fixed a bug with rebuilding timeout
#
# Version 0.84  (2007-09-16) me
# - added CAPA command (RFC 2449)
# - added support for SASL (RFC 2222/4422 + 1734)
# - added SASL mechanisms PLAIN, LOGIN and CRAM-MD5
# - changed status details about authentication
#
# Version 0.83  (2007-09-03) me
# - creating pop3.dat, session.dat and session.lck if they doesn't exist
#
# Version 0.82  (2007-05-26) me
# - added checks if mbox file is available and writeable
#
# Version 0.81  (2007-05-01) me
# - fixed a bug with incorrect mailcounts after delete
# - added extra header "INetSim-ID" (to speed up size calculations etc.)
# - added timeout value for &merge_avail_mbox_files
# - added timeout value for rewrite of session-mbox
# - added value for maximum mailcount
# - changed logging of uidl and list command to prevent logfile-DoS
# - fixed a bug with no mails after datafile cleanup
# - ToDo: * timeout for new merge of mbox files should be added to config
#         * timeout for rebuild of session mbox should be added to config
#         * maximum mailcount should be added to config
#         * deleted-flag should be removed from extra header
#
# Version 0.80  (2007-04-29) me
# - rewrote module for use without IPC::Shareable
# - added new ConfigParameter "POP3_MBOXDirName"
# - added function to generate unique mail-ids (sha1)
# - added function to merge available mbox files
# - added function for random selection of mails from merged mbox
#
# Version 0.76  (2007-04-26) th
# - use getConfigParameter
#
# Version 0.75  (2007-04-26) me
# - fixed a ugly bug in &spoolupdate with remaining messages after delete
#
# Version 0.74  (2007-04-25) th
# - use single global shareable hash instead of multiple variables/arrays
#
# Version 0.73  (2007-04-24) me
# - changed failed message and exit() if mbox is not available
#   to warning message only - no exit
#
# Version 0.72  (2007-04-21) th
# - changed check if mbox file is available
#
# Version 0.71  (2007-04-21) me
# - added logging of status for use with &INetSim::Report::GenReport()
#
# Version 0.70  (2007-04-19) me
# - fixed logging for UIDL command
#
# Version 0.69  (2007-04-19) me
# - fixed incorrect LIST, STAT and UIDL commands (new bug
#   because of the previous handling-fixes in 0.68)
# - fixed possible unlock without authentication
# - fixed possible maildrop change without authentication
# - global array handling changed
#
# Version 0.68  (2007-04-18) me
# - locking mechanism added
# - fixed incorrect handling of DELE, RSET, RETR and QUIT
#   commands (according to RFC "Update-State")
#
# Version 0.67  (2007-04-10) th
# - get fake time via &INetSim::FakeTime::get_faketime()
#   instead of accessing $INetSim::Config::FakeTimeDelta
# - fixed double 'disconnect' message
#
# Version 0.66  (2007-04-05) th
# - changed check for MaxChilds, BindAddress, RunAsUser and
#   RunAsGroup
#
# Version 0.65  (2007-03-27) th
# - use IPC::Shareable to share POP3 spool info
#
# Version 0.6   (2007-03-26) th
# - rewrote module to use INetSim::GenericServer
#
# Version 0.51  (2007-03-18) th
# - added configuration options
#   $INetSim::Config::POP3_Banner
#   $INetSim::Config::POP3_Hostname
#
# Version 0.5   (2007-03-16) me
#
#############################################################
