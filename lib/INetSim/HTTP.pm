# -*- perl -*-
#
# INetSim::HTTP - An HTTP server with real and fake mode
#
# RFC 2616 and others - HYPERTEXT TRANSFER PROTOCOL (HTTP)
#
# (c)2007-2014 Thomas Hungenberg, Matthias Eckert
#
# Version 0.77  (2014-05-23)
#
# For history/changelog see bottom of this file.
#
#############################################################

package INetSim::HTTP;

use strict;
use warnings;
use base qw(INetSim::GenericServer);
use Digest::SHA;

my $SSL = 0;
eval { require IO::Socket::SSL; };
if (! $@) { $SSL = 1; };



my $RE_validIPPort = qr/^(([01]?[0-9][0-9]?|2[0-4][0-9]|25[0-5])\.){3}([01]?[0-9][0-9]?|2[0-4][0-9]|25[0-5])(\:[0-9]{1,5}|)$/;
my $RE_validHostnamePort = qr/^[a-zA-Z0-9]([-a-zA-Z0-9]*[a-zA-Z0-9]|)(\:[0-9]{1,5}|)$/;
my $RE_validFQDNHostnamePort = qr/^([a-zA-Z0-9]([-a-zA-Z0-9]*[a-zA-Z0-9]|)\.)+[a-zA-Z]+(\:[0-9]{1,5}|)$/;



sub configure_hook {
    my $self = shift;
    my $server = $self->{server};

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
        $self->{servicename} = &INetSim::Config::getConfigParameter("HTTPS_ServiceName");
        if (! $SSL) {
            &INetSim::Log::MainLog("failed! Library IO::Socket::SSL not installed", $self->{servicename});
            exit 1;
        }
        $self->{ssl_key} = $self->{cert_dir} . (defined &INetSim::Config::getConfigParameter("HTTPS_KeyFileName") ? &INetSim::Config::getConfigParameter("HTTPS_KeyFileName") : &INetSim::Config::getConfigParameter("Default_KeyFileName"));
        $self->{ssl_crt} = $self->{cert_dir} . (defined &INetSim::Config::getConfigParameter("HTTPS_CrtFileName") ? &INetSim::Config::getConfigParameter("HTTPS_CrtFileName") : &INetSim::Config::getConfigParameter("Default_CrtFileName"));
        $self->{ssl_dh} = (defined &INetSim::Config::getConfigParameter("HTTPS_DHFileName") ? &INetSim::Config::getConfigParameter("HTTPS_DHFileName") : &INetSim::Config::getConfigParameter("Default_DHFileName"));
        if (! -f $self->{ssl_key} || ! -r $self->{ssl_key} || ! -f $self->{ssl_crt} || ! -r $self->{ssl_crt} || ! -s $self->{ssl_key} || ! -s $self->{ssl_crt}) {
            &INetSim::Log::MainLog("failed! Unable to read SSL certificate files", $self->{servicename});
            exit 1;
        }
        #
        $self->{ssl_enabled} = 1;
        $self->{server}->{port} = &INetSim::Config::getConfigParameter("HTTPS_BindPort");  # bind to port
        $self->{http_version} = &INetSim::Config::getConfigParameter("HTTPS_Version");
        $self->{http_fakemode} = &INetSim::Config::getConfigParameter("HTTPS_FakeMode");
        $self->{mimetypes_filename} = &INetSim::Config::getConfigParameter("HTTPS_MIMETypesFileName");
        $self->{document_root} = &INetSim::Config::getConfigParameter("HTTPS_DocumentRoot");
        $self->{fakeFileDir} = &INetSim::Config::getConfigParameter("HTTPS_FakeFileDir");
        $self->{postdata_dirname} = &INetSim::Config::getConfigParameter("HTTPS_POSTDataDir");
	$self->{fakefile_exttoname} = &INetSim::Config::getConfigParameter("HTTPS_FakeFileExtToName");
	$self->{fakefile_exttomimetype} = &INetSim::Config::getConfigParameter("HTTPS_FakeFileExtToMIMEType");
	$self->{default_fakefilename} = &INetSim::Config::getConfigParameter("HTTPS_Default_FakeFileName");
	$self->{default_fakefilemimetype} = &INetSim::Config::getConfigParameter("HTTPS_Default_FakeFileMIMEType");
	$self->{static_fakefile_pathtoname} = &INetSim::Config::getConfigParameter("HTTPS_Static_FakeFilePathToName");
	$self->{static_fakefile_pathtomimetype} = &INetSim::Config::getConfigParameter("HTTPS_Static_FakeFilePathToMIMEType");
    }
    else {
        $self->{servicename} = &INetSim::Config::getConfigParameter("HTTP_ServiceName");
        $self->{ssl_key} = $self->{cert_dir} . (defined &INetSim::Config::getConfigParameter("HTTP_KeyFileName") ? &INetSim::Config::getConfigParameter("HTTP_KeyFileName") : &INetSim::Config::getConfigParameter("Default_KeyFileName"));
        $self->{ssl_crt} = $self->{cert_dir} . (defined &INetSim::Config::getConfigParameter("HTTP_CrtFileName") ? &INetSim::Config::getConfigParameter("HTTP_CrtFileName") : &INetSim::Config::getConfigParameter("Default_CrtFileName"));
        $self->{ssl_dh} = (defined &INetSim::Config::getConfigParameter("HTTP_DHFileName") ? &INetSim::Config::getConfigParameter("HTTP_DHFileName") : &INetSim::Config::getConfigParameter("Default_DHFileName"));
        $self->{ssl_enabled} = 0;
        $self->{server}->{port} = &INetSim::Config::getConfigParameter("HTTP_BindPort");  # bind to port
        $self->{http_version} = &INetSim::Config::getConfigParameter("HTTP_Version");
        $self->{http_fakemode} = &INetSim::Config::getConfigParameter("HTTP_FakeMode");
        $self->{mimetypes_filename} = &INetSim::Config::getConfigParameter("HTTP_MIMETypesFileName");
        $self->{document_root} = &INetSim::Config::getConfigParameter("HTTP_DocumentRoot");
        $self->{fakeFileDir} = &INetSim::Config::getConfigParameter("HTTP_FakeFileDir");
        $self->{postdata_dirname} = &INetSim::Config::getConfigParameter("HTTP_POSTDataDir");
	$self->{fakefile_exttoname} = &INetSim::Config::getConfigParameter("HTTP_FakeFileExtToName");
	$self->{fakefile_exttomimetype} = &INetSim::Config::getConfigParameter("HTTP_FakeFileExtToMIMEType");
	$self->{default_fakefilename} = &INetSim::Config::getConfigParameter("HTTP_Default_FakeFileName");
	$self->{default_fakefilemimetype} = &INetSim::Config::getConfigParameter("HTTP_Default_FakeFileMIMEType");
	$self->{static_fakefile_pathtoname} = &INetSim::Config::getConfigParameter("HTTP_Static_FakeFilePathToName");
	$self->{static_fakefile_pathtomimetype} = &INetSim::Config::getConfigParameter("HTTP_Static_FakeFilePathToMIMEType");
    }

    # warn about missing dh file and disable
    if (defined $self->{ssl_dh} && $self->{ssl_dh}) {
        $self->{ssl_dh} = $self->{cert_dir} . $self->{ssl_dh};
        if (! -f $self->{ssl_dh} || ! -r $self->{ssl_dh}) {
            &INetSim::Log::MainLog("Warning: Unable to read Diffie-Hellman parameter file '$self->{ssl_dh}'", $self->{servicename});
            $self->{ssl_dh} = undef;
        }
    }

    $self->{maxchilds} = &INetSim::Config::getConfigParameter("Default_MaxChilds");


    $self->{default_documents} = "index.html index.htm";

    $self->{error_text}{100} = "Continue";
    $self->{error_text}{101} = "Switching Protocols";
    $self->{error_text}{200} = "OK";
    $self->{error_text}{201} = "Created";
    $self->{error_text}{202} = "Accepted";
    $self->{error_text}{203} = "Non-Authoritative Information";
    $self->{error_text}{204} = "No Content";
    $self->{error_text}{205} = "Reset Content";
    $self->{error_text}{206} = "Partial Content";
    $self->{error_text}{300} = "Multiple Choices";
    $self->{error_text}{301} = "Moved Permanently";
    $self->{error_text}{302} = "Moved Temporarily";
    $self->{error_text}{303} = "See Other";
    $self->{error_text}{304} = "Not Modified";
    $self->{error_text}{305} = "Use Proxy";
    $self->{error_text}{400} = "Bad Request";
    $self->{error_text}{401} = "Unauthorized";
    $self->{error_text}{402} = "Payment Required";
    $self->{error_text}{403} = "Forbidden";
    $self->{error_text}{404} = "Not Found";
    $self->{error_text}{405} = "Method Not Allowed";
    $self->{error_text}{406} = "Not Acceptable";
    $self->{error_text}{407} = "Proxy Authentication Required";
    $self->{error_text}{408} = "Request Time-out";
    $self->{error_text}{409} = "Conflict";
    $self->{error_text}{410} = "Gone";
    $self->{error_text}{411} = "Length Required";
    $self->{error_text}{412} = "Precondition Failed";
    $self->{error_text}{413} = "Request Entity Too Large";
    $self->{error_text}{414} = "Request-URI Too Large";
    $self->{error_text}{415} = "Unsupported Media Type";
    $self->{error_text}{500} = "Internal Server Error";
    $self->{error_text}{501} = "Method Not Implemented";
    $self->{error_text}{502} = "Bad Gateway";
    $self->{error_text}{503} = "Service Unavailable";
    $self->{error_text}{504} = "Gateway Time-out";
    $self->{error_text}{505} = "HTTP Version not supported";


    # read mime types
    if (! open (MIMEFILE, "< $self->{mimetypes_filename}")) {
        &INetSim::Log::MainLog("Warning: Unable to open MIME types file '$self->{mimetypes_filename}': $!", $self->{servicename});
        &INetSim::Log::MainLog("Warning: No MIME types available. Using built-in MIME types instead.", $self->{servicename});
	# if mime types file is not available, set some basic mime types
        $self->{mimetypes}{'htm'} = 'text/html';
        $self->{mimetypes}{'html'} = 'text/html';
        $self->{mimetypes}{'shtml'} = 'text/html';
    }
    else {
	# build mime types database
        my @columns;
        my $mimetype;
        my $extension;
        while (<MIMEFILE>) {
	    s/^[\s]+//g;     # remove leading blanks
	    s/[\r\n]+$//g;   # remove trailing line breaks
	    next if /^[\#]/; # skip comments
	    @columns = split (/\s+/);
	    $mimetype = shift @columns;
	    next unless (@columns);
	    foreach $extension (@columns) {
	        $self->{mimetypes}{$extension} = $mimetype;
	    }
        }
        close (MIMEFILE);
    }
#    foreach (keys %{$self->{mimetypes}}) {
#	print STDOUT "$_ $self->{mimetypes}{$_}\n";
#    }

    # check DocumentRoot directory
    if (! -d $self->{document_root}) {
	&INetSim::Log::MainLog("failed! DocumentRoot directory '$self->{document_root}' does not exist", $self->{servicename});
	exit 1;
    }

    # check FakeFile directory
    if (! -d $self->{fakeFileDir}) {
	&INetSim::Log::MainLog("failed! FakeFile directory '$self->{fakeFileDir}' does not exist", $self->{servicename});
	exit 1;
    }

    # check POST data directory
    $self->{postdata_dirname} =~ /^(.*)$/; # evil untaint!
    $self->{postdata_dirname} = $1;
    if (! -d $self->{postdata_dirname}) {
	&INetSim::Log::MainLog("failed! POST data directory '$self->{postdata_dirname}' does not exist", $self->{servicename});
	exit 1;
    }
    my ($dev, $inode, $mode, $nlink, $uid, $gid, $rdev, $size, $atime, $mtime, $ctime, $blksize, $blocks, $grpname) = undef;

    $gid = getgrnam("inetsim");
    if (! defined $gid) {
	&INetSim::Log::MainLog("Warning: Unable to get GID for group 'inetsim'", $self->{servicename});
    }
    chown -1, $gid, $self->{postdata_dirname};
    ($dev, $inode, $mode, $nlink, $uid, $gid, $rdev, $size, $atime, $mtime, $ctime, $blksize, $blocks) = stat $self->{postdata_dirname};

    # check for group owner 'inetsim'
    $grpname = getgrgid $gid;
    if ($grpname ne "inetsim") {
	&INetSim::Log::MainLog("Warning: Group owner of POST data directory '$self->{postdata_dirname}' is not 'inetsim' but '$grpname'", $self->{servicename});
    }
    # check for group r/w permissions
    if ((($mode & 0060) >> 3) != 6) {
	&INetSim::Log::MainLog("Warning: No group r/w permissions on POST data directory '$self->{postdata_dirname}'", $self->{servicename});
    }
}


sub pre_loop_hook {
    my $self = shift;

    $0 = 'inetsim_' . $self->{servicename};
    &INetSim::Log::MainLog("started (PID $$)", $self->{servicename});
}


sub pre_server_close_hook {
    my $self = shift;

    &INetSim::Log::MainLog("stopped (PID $$)", $self->{servicename});
}


sub fatal_hook {
    my $self = shift;

    &INetSim::Log::MainLog("failed!", $self->{servicename});
    exit 1;
}


sub process_request {
    my $self = shift;
    my $client = $self->{server}->{client};
    my $rhost = $self->{server}->{peeraddr};
    my $rport = $self->{server}->{peerport};

    if ($self->{ssl_enabled} && ! $self->upgrade_to_ssl()) {
        &INetSim::Log::SubLog("[$rhost:$rport] connect", $self->{servicename}, $$);
        &INetSim::Log::SubLog("[$rhost:$rport] info: Error setting up SSL:  $self->{last_ssl_error}", $self->{servicename}, $$);
        &INetSim::Log::SubLog("[$rhost:$rport] disconnect", $self->{servicename}, $$);
        return;
    }
    elsif ($self->{server}->{numchilds} >= $self->{maxchilds}) {
        &INetSim::Log::SubLog("[$rhost:$rport] connect", $self->{servicename}, $$);
        print $client "Maximum number of connections ($self->{maxchilds}) exceeded.\n";
        &INetSim::Log::SubLog("[$rhost:$rport] Connection refused - maximum number of connections ($self->{maxchilds}) exceeded.", $self->{servicename}, $$);
        &INetSim::Log::SubLog("[$rhost:$rport] disconnect", $self->{servicename}, $$);
        return;
    }

    &INetSim::Log::SubLog("[$rhost:$rport] connect", $self->{servicename}, $$);

    $self->{http_request}{method} = "";
    $self->{http_request}{request_uri} = "";
    $self->{http_request}{request_uri_orig} = "";
    $self->{http_request}{request_uri_decoded} = undef;
    $self->{http_request}{version} = "";
    $self->{http_request}{headers} = ();
    $self->{http_request}{pathfile} = "";

    $self->{postdata_pathfile} = "";

    $self->{http_response}{body} = "";
    $self->{http_response}{status} = 0;
    $self->{http_response}{errormessage} = "";
    $self->{http_response}{filename} = "";

    $self->{http_response}{headers} = {}; 
    $self->{http_response}{headers}{'Connection'} = "Close"; 
    $self->{http_response}{headers}{'Server'} = $self->{http_version};

    # read HTTP request
    if ($self->read_http_request) {

	if ($self->{http_response}{status}) {
	    # error in processing request header
	    $self->send_http_response;
	}
	else {
	    # log requested URL
	    my $fullreq;
	    if (($self->{http_request}{request_uri_orig} !~ /^https?:\/\//) && (defined $self->{http_request}{headers}{'Host'})) { 
		if ($self->{ssl_enabled}) {
		    $fullreq = "https://" . $self->{http_request}{headers}{'Host'} . $self->{http_request}{request_uri_orig};
		}
		else {
		    $fullreq = "http://" . $self->{http_request}{headers}{'Host'} . $self->{http_request}{request_uri_orig};
		}
	    }
	    else {
		$fullreq = $self->{http_request}{request_uri_orig};
	    }
	    # replace non-printable characters with "<NP>" before logging
	    $fullreq =~ s/[^\x20-\x7e]/\<NP\>/g;
	    &INetSim::Log::SubLog("[$rhost:$rport] info: Request URL: $fullreq", $self->{servicename}, $$);

	    # if request contains hex encoded chars, log decoded request
	    if (defined $self->{http_request}{request_uri_decoded}) {
		if (($self->{http_request}{request_uri_orig} !~ /^https?:\/\//) && (defined $self->{http_request}{headers}{'Host'})) { 
		    if ($self->{ssl_enabled}) {
			$fullreq = "https://" . $self->{http_request}{headers}{'Host'} . $self->{http_request}{request_uri_decoded};
		    }
		    else {
			$fullreq = "http://" . $self->{http_request}{headers}{'Host'} . $self->{http_request}{request_uri_decoded};
		    }
		}
		else {
		    $fullreq = $self->{http_request}{request_uri_decoded};
		}
		# replace non-printable characters with "<NP>" before logging
		$fullreq =~ s/[^\x20-\x7e]/\<NP\>/g;
		&INetSim::Log::SubLog("[$rhost:$rport] info: Decoded URL: $fullreq", $self->{servicename}, $$);
	    }

	    # for HEAD/GET/POST requests read fake/real file
	    if (($self->{http_request}{method} eq "HEAD") || ($self->{http_request}{method} eq "GET") || ($self->{http_request}{method} eq "POST")) {
		if($self->{http_fakemode}) {
		    if (defined $self->{http_request}{headers}{Host} && $self->{http_request}{headers}{Host} =~ /^checkip\.dyndns\.(org|com)/i) {
			$self->fake_dyndns;
		    }
		    elsif (defined ($fullreq) && ($fullreq =~ /.*\/wpad.dat$/i || $fullreq =~ /.*\/proxy.pac$/i)) {
			$self->send_wpadfile;
		    }
		    else {
			$self->read_fakefile;
		    }
		}
		else {
		    $self->read_file;
		}
	    }
	    # for OPTIONS request, set response headers
	    elsif ($self->{http_request}{method} eq "OPTIONS") {
		$self->{http_response}{headers}{'Content-Length'} = 0;
		$self->set_response_status(200);
	    }

	    # no status set - should not occur
	    if (!$self->{http_response}{status}) {
		$self->set_response_status(500, "Do not know how to handle your request.");
	    }

	    # send HTTP response
	    $self->send_http_response;
	}
    }
    if ($@ !~ /TIMEOUT/) {
	&INetSim::Log::SubLog("[$rhost:$rport] disconnect", $self->{servicename}, $$);
    }
}


sub read_http_request {
    my $self = shift;
    my $server = $self->{server};
    my $client = $server->{client};
    my $rhost = $server->{peeraddr};
    my $rport = $server->{peerport};
    my $timeout = &INetSim::Config::getConfigParameter("Default_TimeOut");

    my @request = ();

    eval {
	local $SIG{'ALRM'} = sub { die "TIMEOUT" };
	alarm($timeout);

	# read full request from client
	while (<$client>) {
	    alarm($timeout);
	    s/[\r\n]+$//g;
	    if ($_ ne "") {
		# check for non-printable characters
		if (! /^[\x20-\x7e]+$/) {
		    s/[^\x20-\x7e]/\./g;
		    &INetSim::Log::SubLog("[$rhost:$rport] recv: $_", $self->{servicename}, $$);
		    $self->set_response_status(400, "Your request contains illegal non-printable characters.");
		    return 1;
		}
		else {
		    push (@request, $_);
		    &INetSim::Log::SubLog("[$rhost:$rport] recv: $_", $self->{servicename}, $$);
		}
	    }
	    last if ($_ eq "");
	}
	alarm(0);
    };
    if ($@ =~ /TIMEOUT/) {
	&INetSim::Log::SubLog("[$rhost:$rport] disconnect (timeout)", $self->{servicename}, $$);
	return 0;
    }

    if (scalar @request == 0) {
	# no data received
	&INetSim::Log::SubLog("[$rhost:$rport] info: Client sent no data", $self->{servicename}, $$);
	return 0;
    }

    # get first line of request
    my $first_line = shift @request;

    # must be of format METHOD REQUEST-URI HTTP-VERSION
    my @args = split(/ /, $first_line);

    if ((scalar @args) != 3) {
	$self->set_response_status(400); # Bad Request
	return 1;
    }

    # implemented methods
    if (($args[0] eq "GET") ||
	($args[0] eq "HEAD") ||
	($args[0] eq "POST") ||
	($args[0] eq "OPTIONS")) {
	$self->{http_request}{method} = $args[0];
    }
    else {
	$self->set_response_status(501, "Method '$args[0]' not implemented.");
	$self->{http_response}{headers}{'Allow'} = "GET, HEAD, POST, OPTIONS";
	return 1;
    }

    # supported versions
    if (($args[2] eq "HTTP/1.0") || ($args[2] eq "HTTP/1.1")) {
	$self->{http_request}{version} = $args[2];
    }
    else {
	$self->set_response_status(505, "Version '$args[2]' not supported.");
	return 1;
    }

    # check if Request-URI is absoluteURI or abs_path (RFC 2616)
    # (starts with "/" or "http[s]://")
    if ($args[1] !~ /^(\/|\*|https?:\/\/)/) {
	$self->set_response_status(400); # Bad Request
	return 1;
    }

    # store original Request-URI
    $self->{http_request}{request_uri_orig} = $args[1];

    # decode hex chars in Request-URI
    my $request_uri_decoded = $args[1];
    my $chars_decoded = 0;
    my $prefix = "";
    my $hexchars = "";
    my $suffix = "";
    my $dec = 0;
    while ($request_uri_decoded =~ /^(.*)\%(..)(.*)$/) {
	$prefix = $1;
	$hexchars = $2;
	$suffix = $3;
	$chars_decoded++;
	# check for malformed hex characters
	if ($hexchars !~ /^[0-9a-fA-F][0-9a-fA-F]$/) {
	    $self->set_response_status(400, "Your request contains malformed hex characters.");
	    return 1;
	}
	else {
	    $dec = hex($hexchars);
	    # check for non-printable characters
	    if (($dec < 32) || ($dec > 127)) {
		$self->set_response_status(400, "Your request contains illegal characters in hex notation.");
		return 1;
	    }
	    $request_uri_decoded = $prefix . chr($dec) . $suffix;
	}
    }

    # check if decoded Request-URI still contains an '%'
    if ($request_uri_decoded =~ /\%/) {
	$self->set_response_status(400, "Your request contains malformed hex notation.");
	return 1;
    }

    # store Request-URI
    if ($chars_decoded > 0) {
	$self->{http_request}{request_uri_decoded} = $request_uri_decoded;
	$self->{http_request}{request_uri} = $request_uri_decoded;
    }
    else {
	$self->{http_request}{request_uri} = $self->{http_request}{request_uri_orig};
    }

    # check Request-URI for illegal characters
    # NEEDS WORK!
#    if ($self->{http_request}{request_uri} =~ /[\@\:]/) {
#	$self->set_response_status(400, "Your request contains illegal characters.");
#	return 1;
#    }


    # get additional HTTP headers
    my $key;
    my $value;
    foreach (@request) {

        /^([^: ]+)(: )(.*)$/;

	if (! defined $2) {
	    $self->set_response_status(400, "Invalid header.");
	    return 1;
	}

	$key = $1;
	$value = $3;

	if (defined $key && defined $value) {
	    if ($value =~ /^[\s]+$/) {
		$self->set_response_status(400, "Invalid header.");
		return 1;
	    }
	    else {
		$self->{http_request}{headers}{$key} = $value;
	    }
	}
	else {
	    $self->set_response_status(400);
	    return 1;
	}
    }


    # HTTP/1.1 needs "Host" header
    if ($self->{http_request}{version} eq "HTTP/1.1") {
	if (! defined $self->{http_request}{headers}{'Host'}) {
	    # no 'Host' header
	    $self->set_response_status(400);
	    return 1;
	}
	if (!(($self->{http_request}{headers}{'Host'} =~ $RE_validIPPort) || ($self->{http_request}{headers}{'Host'} =~ $RE_validHostnamePort) || ($self->{http_request}{headers}{'Host'} =~ $RE_validFQDNHostnamePort))) {
	    # no valid IP or (fqdn) hostname
	    $self->set_response_status(400);
	    return 1;
	}
    }


    # ignore everything after first '?'
    my @parts = split(/\?/, $self->{http_request}{request_uri});
    my $req = $parts[0];

    if ($req =~ /^https?:\/\//) {
	# absoluteURI
	$req =~ /^(https?:\/\/)([^\/]*)(|\/.*)$/;
	my $host = "";
	my $pathfile = "";
	if (defined $2) {
	    $host = $2;
	}
	if (defined $3) {
	    $pathfile = $3;
	}

	if ($host eq "") {
	    # invalid absoluteURI
	    $self->set_response_status(400);
	    return 1;
	}
	else {
	    if (!(($host =~ $RE_validIPPort) || ($host =~ $RE_validHostnamePort) || ($host =~ $RE_validFQDNHostnamePort))) {
		# no valid IP or (fqdn) hostname
		$self->set_response_status(400);
		return 1;
	    }

	    if ($pathfile ne "") {
		$self->{http_request}{pathfile} = $pathfile;
	    }
	    else {
		$self->{http_request}{pathfile} = "/";
	    }
	}
    }
    else {
	# abs_path
	$self->{http_request}{pathfile} = $req;
    }


    # remove trailing slashes
#    $self->{http_request}{pathfile} =~ s/[\/]+$//g;
    # check for directory traversal "/.."
    if ($self->{http_request}{pathfile} =~ /\/\.\./) {
	$self->set_response_status(403, "Specification of parent directories not allowed.");
	return 1;
    }

    if ($self->{http_request}{method} eq "POST") {
	# read and store POST data

	# check Content-Length header
	if (defined $self->{http_request}{headers}{'Content-Length'}) {

	    my $contentLength = $self->{http_request}{headers}{'Content-Length'};

	    if ($contentLength !~ /^[0-9]+$/) {
		$self->set_response_status(400, "Invalid Content-Length header value.");
		return 1;
	    }

	    if ($contentLength > 1000000) {
		$self->set_response_status(400, "Content-Length header value larger than 1000000.");
		return 1;
	    }

	    if ($contentLength > 0) {
		# initialize random number generator
		srand(time() ^($$ + ($$ <<15)));

		my $sha = Digest::SHA->new();
		$sha->add(int(rand(100000000)));
		$sha->add(time());
		my $postFileName = $self->{postdata_dirname} . "/" . $sha->hexdigest;
		$self->{postdata_pathfile} = $postFileName;

		if (! open (POSTFILE, "> $postFileName")) {
		    &INetSim::Log::MainLog("Error: Unable to create HTTP POST data file '$postFileName'", $self->{servicename});
		}
		else {
		    binmode (POSTFILE);
		    chmod 0660, $postFileName;
		    eval {
			local $SIG{'ALRM'} = sub { die "TIMEOUT" };
			alarm($timeout);
			my $buffer;
			my $bytesRead = read $client, $buffer, $contentLength;

#			print STDOUT "Content-Length: $contentLength\n";
#			print STDOUT "Bytes read: $bytesRead\n";

			print POSTFILE $buffer;

			&INetSim::Log::SubLog("[$rhost:$rport] recv: <(POSTDATA)>", $self->{servicename}, $$);

			if ($contentLength != $bytesRead) {
			    &INetSim::Log::SubLog("[$rhost:$rport] info: Content-Length header value is $contentLength, but client sent only $bytesRead bytes", $self->{servicename}, $$);
			}

			alarm(0);
		    };
		    close POSTFILE;
		    &INetSim::Log::SubLog("[$rhost:$rport] info: POST data stored to: $postFileName", $self->{servicename}, $$);
		    if ($@ =~ /TIMEOUT/) {
			&INetSim::Log::SubLog("[$rhost:$rport] disconnect (timeout)", $self->{servicename}, $$);
			return 0;
		    }
		}
	    }
	    else {
		# Content-Length is 0
		&INetSim::Log::SubLog("[$rhost:$rport] info: 'Content-Length' header value is 0 - not storing POST data", $self->{servicename}, $$);
	    }
	}
	else {
	    # no Content-Length header
	    &INetSim::Log::SubLog("[$rhost:$rport] info: Client did not send 'Content-Length' header - not storing POST data", $self->{servicename}, $$);
	}
    }
    elsif ($self->{http_request}{method} eq "OPTIONS") {
	$self->{http_response}{headers}{'Allow'} = "GET, HEAD, POST, OPTIONS";
    }

    return 1;
}


sub send_http_response {
    my $self = shift;
    my $server = $self->{server};
    my $client = $server->{client};
    my $rhost = $server->{peeraddr};
    my $rport = $server->{peerport};

    $self->{http_response}{headers}{'Date'} = &get_gmdate();

    # if error occured, generate body
    if ($self->{http_response}{status} >= 400) {
	$self->{http_response}{headers}{'Content-Type'} = "text/html";

	$self->{http_response}{body} .= "<html>\n";
	$self->{http_response}{body} .= "  <head>\n";
	$self->{http_response}{body} .= "    <title>$self->{http_response}{status} $self->{error_text}{$self->{http_response}{status}}</title>\n";
	$self->{http_response}{body} .= "  </head>\n";
	$self->{http_response}{body} .= "  <body>\n";
	$self->{http_response}{body} .= "    <h1>$self->{error_text}{$self->{http_response}{status}}</h1>\n";
	$self->{http_response}{body} .= "    <p>Your browser sent a request that this server could not understand.</p>\n";

	if ($self->{http_response}{errormessage}) {
	    $self->{http_response}{body} .= "    <p>$self->{http_response}{errormessage}</p>\n";
	}

	$self->{http_response}{body} .= "  <hr />\n";
	$self->{http_response}{body} .= "  <address>" . $self->{http_version} . "</address>\n";
	$self->{http_response}{body} .= "  </body>\n";
	$self->{http_response}{body} .= "</html>\n";
    }

    # place headers into response
    my $buffer = "HTTP/1.1 $self->{http_response}{status} $self->{error_text}{$self->{http_response}{status}}\r\n";
    &INetSim::Log::SubLog("[$rhost:$rport] send: HTTP/1.1 $self->{http_response}{status} $self->{error_text}{$self->{http_response}{status}}", $self->{servicename}, $$);

    foreach my $header (keys %{$self->{http_response}{headers}}) {
	$buffer .= "$header: $self->{http_response}{headers}{$header}\r\n";
	&INetSim::Log::SubLog("[$rhost:$rport] send: $header: $self->{http_response}{headers}{$header}", $self->{servicename}, $$);
    }
    $buffer .= "\r\n";

    # send header to client
    print $client $buffer;

    # send body to client
    if (($self->{http_request}{method} eq "GET") || ($self->{http_request}{method} eq "POST")) {
	print $client $self->{http_response}{body};
	if ($self->{http_response}{filename} ne "") {
	    &INetSim::Log::SubLog("[$rhost:$rport] info: Sending file: $self->{http_response}{filename}", $self->{servicename}, $$);
	}
    }

    my $url;
    if (($self->{http_request}{request_uri_orig} !~ /^https?:\/\//) && (defined $self->{http_request}{headers}{'Host'})) { 
	if ($self->{ssl_enabled}) {
	    $url = "https://" . $self->{http_request}{headers}{'Host'} . $self->{http_request}{request_uri_orig};
	}
	else {
	    $url = "http://" . $self->{http_request}{headers}{'Host'} . $self->{http_request}{request_uri_orig};
	}
    }
    else {
	$url = $self->{http_request}{request_uri_orig};
    }
    if ($self->{http_response}{status} < 400) {
	&INetSim::Log::SubLog("[$rhost:$rport] stat: 1 method=$self->{http_request}{method} url=$url sent=$self->{http_response}{filename} postdata=$self->{postdata_pathfile}", $self->{servicename}, $$);
    } else {
	&INetSim::Log::SubLog("[$rhost:$rport] stat: 0 method=$self->{http_request}{method} url=$url sent=$self->{http_response}{filename} postdata=$self->{postdata_pathfile}", $self->{servicename}, $$);
    }
}


sub set_response_status {
    my $self = shift;
    my $statuscode = shift;
    my $errormessage = shift;

    $self->{http_response}{status} = $statuscode;
    $self->{http_response}{errormessage} = $errormessage;
}


sub read_file {
    my $self = shift;

    my $filename = $self->{document_root} . $self->{http_request}{pathfile};

    if (! -e $filename) {  # check if filepath exists
	$self->set_response_status(404, "No such file or directory.");
	return;
    }
    elsif (! -r $filename) {  # check if filepath is readable
	$self->set_response_status(403, "Permission denied.");
	return;
    }
    else {
	if (-d $filename) {  # filepath is a directory
	    # check if it contains a default document
	    my @default_documents = split (/\s+/, $self->{default_documents});
	    my $newfilename = "";
	    foreach (@default_documents) {
		my $checkfilename = $filename . "/" . $_;
		if (-e $checkfilename) {
		    $newfilename = $checkfilename;
		    last;
		}
	    }
	    if ($newfilename eq "") {
		# no default document found
		$self->set_response_status(403, "Directory listing not allowed.");
		return;
	    }
	    else {
		# default document found
		$filename = $newfilename;
		if (! -r $filename) {
		    $self->set_response_status(403, "Permission denied.");
		    return;
		}
	    }
	}

	$self->{http_response}{filename} = $filename;

	# read the file into HTTP response body

	# determine file size
	my $filesize = (-s $filename);
	$self->{http_response}{headers}{'Content-Length'} = $filesize;
	
	# read file
	open (FILE, "<$filename") or $self->error_exit("Unable to open file '$filename': $!");
	binmode (FILE);
	read (FILE, $self->{http_response}{body}, $filesize);
	close (FILE);
	
	# determine Content-Type
	my @parts = split (/\./, $filename);
	my $extension = lc(pop @parts);
	if(defined $self->{mimetypes}{$extension}) {
	    $self->{http_response}{headers}{'Content-Type'} = $self->{mimetypes}{$extension};
	}
	else {
	    $self->{http_response}{headers}{'Content-Type'} = "application/octet-stream";
	}
	
	# set status 200 OK
	$self->set_response_status(200);
    }
}


sub read_fakefile {
    my $self = shift;
    my $server = $self->{server};
    my $client = $server->{client};
    my $rhost = $server->{peeraddr};
    my $rport = $server->{peerport};

    my $fakefilename;

    # check for static fakefile
    if (defined $self->{static_fakefile_pathtoname}{$self->{http_request}{pathfile}}) {
	# configured static fakefile found
	$fakefilename = $self->{fakeFileDir} . "/" . $self->{static_fakefile_pathtoname}{$self->{http_request}{pathfile}};
	# set content-type
	$self->{http_response}{headers}{'Content-Type'} = $self->{static_fakefile_pathtomimetype}{$self->{http_request}{pathfile}};
	&INetSim::Log::SubLog("[$rhost:$rport] info: Sending static fake file configured for path '$self->{http_request}{pathfile}'.", $self->{servicename}, $$);
    }
    else {
	# get extension from requested file
	my $extension = undef;
	my @parts = split (/\./, $self->{http_request}{pathfile});
	if ((scalar @parts) > 1) {
	    $extension = lc(pop @parts);
	}

	# select fake file
	if((defined $extension) && (defined $self->{fakefile_exttoname}{$extension})) {
	    # extension configured
	    $fakefilename = $self->{fakeFileDir} . "/" . $self->{fakefile_exttoname}{$extension};
	    # set content-type
	    $self->{http_response}{headers}{'Content-Type'} = $self->{fakefile_exttomimetype}{$extension};
		&INetSim::Log::SubLog("[$rhost:$rport] info: Sending fake file configured for extension '$extension'.", $self->{servicename}, $$);
	}
	else {
	    # extension not configured, check for default fakefile
	    if((defined $self->{default_fakefilename}) && (defined $self->{default_fakefilemimetype})) {
		$fakefilename = $self->{fakeFileDir} . "/" . $self->{default_fakefilename};
		$self->{http_response}{headers}{'Content-Type'} = $self->{default_fakefilemimetype};
		&INetSim::Log::SubLog("[$rhost:$rport] info: No matching file extension configured. Sending default fake file.", $self->{servicename}, $$);
	    }
	    else {
		# no default fakefile configured - return 404 Not Found
		$self->set_response_status(404, "No such file or directory.");
		&INetSim::Log::SubLog("[$rhost:$rport] warn: No matching file extension or default fake file configured.", $self->{servicename}, $$);
		return;
	    }
	}
    }

    if (! -f $fakefilename) {  # check if fakefile exists
	$self->set_response_status(404, "No such file or directory.");
	&INetSim::Log::SubLog("[$rhost:$rport] warn: Fake file $fakefilename does not exist", $self->{servicename}, $$);
	return;
    }
    elsif (! -r $fakefilename) {  # check if fakefile is readable
	$self->set_response_status(403, "Permission denied.");
	&INetSim::Log::SubLog("[$rhost:$rport] warn: No permission to read fake file $fakefilename", $self->{servicename}, $$);
	return;
    }

    $self->{http_response}{filename} = $fakefilename;

    # determine file size
    my $filesize = (-s $fakefilename);
    $self->{http_response}{headers}{'Content-Length'} = $filesize;

    # read file
    open (FILE, "<$fakefilename") or $self->error_exit("Unable to open fake file '$fakefilename': $!");
    binmode (FILE);
    read (FILE, $self->{http_response}{body}, $filesize);
    close (FILE);

    $self->set_response_status(200);
}



sub fake_dyndns {
    my $self = shift;
    my $server = $self->{server};
    my $client = $server->{client};
    my $rhost = $server->{peeraddr};
    my $rport = $server->{peerport};

    # set server string to dyndns-checkip
    $self->{http_response}{headers}{'Server'} = "DynDNS-CheckIP/1.0";
    # set content-type
    $self->{http_response}{headers}{'Content-Type'} = "text/html";
    # set additional header
    $self->{http_response}{headers}{'Cache-Control'} = "no-cache";
    $self->{http_response}{headers}{'Pragma'} = "no-cache";
    # build content body
    $self->{http_response}{body} = "<html><head><title>Current IP Check</title></head><body>Current IP Address: ".$rhost."</body></html>\r\n";
    # determine content length
    $self->{http_response}{headers}{'Content-Length'} = length($self->{http_response}{body});
    # set filename to 'none' for logging
    $self->{http_response}{filename} = "none";

    $self->set_response_status(200);
}



sub send_wpadfile {
    my $self = shift;
    my $server = $self->{server};
    my $client = $server->{client};
    my $rhost = $server->{peeraddr};
    my $rport = $server->{peerport};
    my $localaddress = &INetSim::Config::getConfigParameter("Default_BindAddress");

    # set content-type
    $self->{http_response}{headers}{'Content-Type'} = "application/x-ns-proxy-autoconfig";
    # build content body
    $self->{http_response}{body} = "function FindProxyForURL(url, host)\n";
    $self->{http_response}{body} .= "{\n";
    $self->{http_response}{body} .= "    if (isInNet(host, \"192.168.1.0\", \"255.255.255.0\"))\n";	# this is an example only, should be removed later !!!
    $self->{http_response}{body} .= "        return \"DIRECT\";\n";
    $self->{http_response}{body} .= "    else\n";
    $self->{http_response}{body} .= "        return \"PROXY $localaddress:8080\";\n";
    $self->{http_response}{body} .= "}\n";
    # determine content length
    $self->{http_response}{headers}{'Content-Length'} = length($self->{http_response}{body});
    # set filename to 'none' for logging
    $self->{http_response}{filename} = "none";

    $self->set_response_status(200);
}



sub get_gmdate {
    # return current GMT date
    my @months = qw(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec);
    my @weekDays = qw(Sun Mon Tue Wed Thu Fri Sat);
    my ($sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst) = gmtime(&INetSim::FakeTime::get_faketime());
    $year += 1900;
    my $gmdate = sprintf("%3s, %02d %3s %4d %02d:%02d:%02d GMT", $weekDays[$wday], $mday, $months[$mon], $year, $hour, $min, $sec);
    return $gmdate;
}



sub upgrade_to_ssl {
    my $self = shift;
    my %ssl_params = (  SSL_version             => "SSLv23",
                        SSL_cipher_list         => "ALL",
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
#        $status{tls_cipher} = lc($result->get_cipher());
        return 1;
    }
    else {
        $self->{last_ssl_error} = IO::Socket::SSL::errstr();
        return 0;
    }
}



sub error_exit {
    my $self = shift;
    my $msg = shift;
    my $server = $self->{server};
    my $client = $server->{client};
    my $rhost = $server->{peeraddr};
    my $rport = $server->{peerport};

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
# Version 0.77   (2014-05-23) th
# - changed SSL_version to "SSLv23"
#
# Version 0.76   (2010-11-03) th
# - add HTTP Version to status code response
#
# Version 0.75   (2010-09-18) th
# - bugfix: HTTPS fakefile mode used configuration for HTTP service
# - bugfix: take care of HTTPs absolute URIs
# - added support for HTTP(S) static fakefiles
#
# Version 0.74   (2009-12-19) me
# - added new configuration variable 'CertDir'
#
# Version 0.73   (2009-10-27) me
# - added support for SSL (https)
# - removed some unnecessary variables
# - added .com as top level domain for dyndns
#
# Version 0.72   (2008-09-05) th
# - added support for OPTIONS method
#
# Version 0.71   (2008-08-27) me
# - added logging of process id
#
# Version 0.70   (2008-08-25) th
# - changed regexp for 'wpad' request matching
#
# Version 0.69   (2008-08-20) me
# - added function 'send_wpadfile()' to FakeMode
#
# Version 0.68   (2008-08-09) th
# - check data directories on startup
#
# Version 0.67   (2008-08-08) th
# - support port numbers in 'Host' header and absoluteURI
#
# Version 0.66   (2008-08-03) th
# - improved HTTP POST support
#
# Version 0.65   (2008-08-02) th
# - added basic support for HTTP POST
#
# Version 0.64   (2008-06-26) th
# - changed status logging for bad requests
#
# Version 0.63   (2008-06-15) th
# - code cleanup
#
# Version 0.62   (2008-06-14) th
# - bugfix in header value parsing
#
# Version 0.61   (2008-06-14) th
# - bugfix in regexp for check of empty header values
#
# Version 0.6    (2008-06-13) th
# - improved handling of Request-URI
# - support absoluteURI (RFC 2616)
#
# Version 0.52   (2008-04-01) th
# - added timeout after client inactivity of n seconds,
#   using new config parameter Default_TimeOut
#
# Version 0.51  (2008-02-27) th
# - temporarily disable a check for invalid chars in request
#   because it causes problems
#
# Version 0.50  (2007-12-31) th
# - change process name
#
# Version 0.49  (2007-10-24) me
# - fixed uninitialized value if host header isn't given
#
# Version 0.48  (2007-10-14) th
# - added "info:" to logging of "Requested URL" and "Sending file" 
#
# Version 0.47  (2007-09-22) me
# - added fake_dyndns() to FakeMode
#
# Version 0.46  (2007-06-05) th
# - decode hex chars in request earlier
# - if request contains hex encoded chars, log decoded request
# - fixed bug in check for malformed hex notation
# - check for non-printable hex-decoded chars
#
# Version 0.45  (2007-06-04) th
# - fixed bug in processing GET queries
#
# Version 0.44  (2007-05-31) th
# - added some comments
#
# Version 0.43  (2007-05-24) th
# - MIME types for fake files are not determined via mime.types anymore
#   but must be specified in configuration file
#
# Version 0.42  (2007-05-07) th
# - check for non-printable characters in request
# - check for illegal hex characters while decoding hex
#
# Version 0.41  (2007-04-27) th
# - fixed uninitialized value when logging 'stat' for a bad request
# - use getConfigParameter, getConfigHash
#
# Version 0.40  (2007-04-25) me
# - changed failed! message and exit() if mimetype file is not
#   available to warning message only - no exit
#
# Version 0.39  (2007-04-22) th
# - added error_exit()
# - replaced die()-calls with error_exit()
# - changed status logging
#
# Version 0.38  (2007-04-21) me
# - added logging of status for use with &INetSim::Report::GenReport()
#
# Version 0.37  (2007-04-21) th
# - fixed if-condition so error messages are returned to client again
# - changed handling of default fake file
#
# Version 0.36  (2007-04-20) th
# - check if fake file exists and is readable
#
# Version 0.35  (2007-04-11) th
# - check if no data was received from client
# - added logging of 'connect' and 'disconnect' messages
#
# Version 0.34  (2007-04-10) th
# - get fake time via &INetSim::FakeTime::get_faketime()
#   instead of accessing $INetSim::Config::FakeTimeDelta
#
# Version 0.33  (2007-04-06) th
# - added logging of files sent
#
# Version 0.32  (2007-04-05) th
# - changed check for MaxChilds, BindAddress, RunAsUser and
#   RunAsGroup
#
# Version 0.31  (2007-03-29) th
# - added function get_gmdate()
# - added FakeMode
#
# Version 0.3   (2007-03-28) th
# - completely rewritten again because the example from
#   Net::Server was crap
#
# Version 0.2   (2007-03-24) th
# - completely rewritten using example from Net::Server
#
# Version 0.1   (2007-03-19) th
#
#############################################################

