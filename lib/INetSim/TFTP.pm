# -*- perl -*-
#
# INetSim::TFTP - A fake TFTP server
#
# RFC 1350 - Trivial File Transfer Protocol
#
# (c)2007-2009 Matthias Eckert, Thomas Hungenberg
#
# Version 0.59   (2009-12-18)
#
# For history/changelog see bottom of this file.
#
#############################################################

package INetSim::TFTP;

use strict;
use warnings;
use POSIX;
use IO::Socket;
use IO::Select;
use Digest::SHA;
use Fcntl ':flock';



# RFC 2347
my %OPT_AVAIL = ( blksize	=> 2,	# RFC 2348
                  timeout	=> 2,	# RFC 2349
                  tsize		=> 1,	# RFC 2349
                  multicast	=> 0	# RFC 2090
);
# status: 3 of 4


my %ERR = ( 0 => "Not defined, see error message",
            1 => "File not found",
            2 => "Access violation",
            3 => "Disk full or allocation exceeded",
            4 => "Illegal TFTP operation",
            5 => "Unknown transfer ID",
            6 => "File already exists",
            7 => "No such user",
            8 => "Terminate transfer due to option negotiation"
);

my %TFTP_OPT;

my %VFS;

my %CONN;




sub configure_hook {
    my $self = shift;
    my ($dev, $inode, $mode, $nlink, $uid, $gid, $rdev, $size, $atime, $mtime, $ctime, $blksize, $blocks, $grpname);

    $self->{server}->{host}   = &INetSim::Config::getConfigParameter("Default_BindAddress"); # bind to address
    $self->{server}->{port}   = &INetSim::Config::getConfigParameter("TFTP_BindPort");
    $self->{server}->{proto}  = 'udp';                                      # UDP protocol
    $self->{server}->{type}  = SOCK_DGRAM;
    $self->{server}->{user}   = &INetSim::Config::getConfigParameter("Default_RunAsUser");       # user to run as
    $self->{server}->{group}  = &INetSim::Config::getConfigParameter("Default_RunAsGroup");    # group to run as

    $self->{servicename} = &INetSim::Config::getConfigParameter("TFTP_ServiceName");
    $self->{maxchilds} = &INetSim::Config::getConfigParameter("Default_MaxChilds");
    $self->{timeout} = &INetSim::Config::getConfigParameter("Default_TimeOut");
    #
    $self->{document_root} = &INetSim::Config::getConfigParameter("TFTP_DocumentRoot");
    $self->{upload_dir} = &INetSim::Config::getConfigParameter("TFTP_UploadDir");
    $self->{allow_overwrite} = &INetSim::Config::getConfigParameter("TFTP_AllowOverwrite");
    $self->{options} = &INetSim::Config::getConfigParameter("TFTP_EnableOptions");
    $self->{sessionfile} = "$self->{upload_dir}/tftp.session";

    $self->{sessionfile} =~ /^(.*)$/; # evil untaint!
    $self->{sessionfile} = $1;

    # check DocumentRoot directory
    if (! -d $self->{document_root}) {
        &INetSim::Log::MainLog("failed! DocumentRoot directory '$self->{document_root}' does not exist", $self->{servicename});
        exit 1;
    }

    # check Upload directory
    $self->{upload_dir} =~ /^(.*)$/; # evil untaint!
    $self->{upload_dir} = $1;
    if (! -d $self->{upload_dir}) {
        &INetSim::Log::MainLog("failed! Upload directory '$self->{upload_dir}' does not exist", $self->{servicename});
        exit 1;
    }

    $gid = getgrnam("inetsim");
    if (! defined $gid) {
        &INetSim::Log::MainLog("Warning: Unable to get GID for group 'inetsim'", $self->{servicename});
    }
    chown -1, $gid, $self->{upload_dir};
    ($dev, $inode, $mode, $nlink, $uid, $gid, $rdev, $size, $atime, $mtime, $ctime, $blksize, $blocks) = stat $self->{upload_dir};

    # check for group owner 'inetsim'
    $grpname = getgrgid $gid;
    if ($grpname ne "inetsim") {
        &INetSim::Log::MainLog("Warning: Group owner of Upload directory '$self->{upload_dir}' is not 'inetsim' but '$grpname'", $self->{servicename});
    }
    # check for group r/w permissions
    if ((($mode & 0060) >> 3) != 6) {
        &INetSim::Log::MainLog("Warning: No group r/w permissions on Upload directory '$self->{upload_dir}'", $self->{servicename});
    }

    # register options from config file
    $self->register_options();

    # initialize the virtual filesystem
    $self->init_VFS;
}



sub pre_loop_hook {
    my $self = shift;

    $0 = 'inetsim_' . $self->{servicename};
    &INetSim::Log::MainLog("started (PID $$)", $self->{servicename});
}



sub pre_server_close_hook {
    my $self = shift;

    $self->_save_vfs_changes();
    &INetSim::Log::MainLog("stopped (PID $$)", $self->{servicename});
}



sub fatal_hook {
    my ($self, $msg) = @_;

    if (defined $msg) {
        $msg =~ s/[\r\n]*//;
        &INetSim::Log::MainLog("failed! $msg", $self->{servicename});
    }
    else {
        &INetSim::Log::MainLog("failed!", $self->{servicename});
    }
    exit 1;
}



sub process_request {
    my $self = shift;
    my $client = $self->{server}->{client};
    my $rhost = $client->peerhost;
    my $rport = $client->peerport;
    my $packet = $self->{server}->{data};
    my $bytes = length($packet);

    # check minimum packet size -> 4 bytes
    ($bytes >= 4) or return;
    # check maximum packet size -> 516 bytes (or 65468 bytes with blocksize option)
    ($bytes <= 516 || ($self->{options} && $bytes <= 65468)) or return;
    # get the opcode
    my ($opcode, $data) = unpack ("n a*", $packet);
    # check opcode
    ($opcode && $opcode < 7) or return;
    # process packet
    if ($opcode == 1) {
        $self->RRQ($data);
    }
    elsif ($opcode == 2) {
        $self->WRQ($data);
    }
    elsif ($opcode == 3) {
        $self->DATA($data);
    }
    elsif ($opcode == 4) {
        $self->ACK($data);
    }
    elsif ($opcode == 5) {
        $self->ERROR($data);
    }
    elsif ($opcode == 6) {
        # OACK
        # don't waste time with option acknowledge packets
    }
}



sub check_timeout {
    my $self = shift;
    my $client;
    my $now = time();

    foreach $client (keys %CONN) {
        my ($rhost, $rport, $request, $file, $timeout, $lastrecv, $lastsend, $retries) = ($CONN{$client}->{rhost}, $CONN{$client}->{rport}, $CONN{$client}->{request}, $CONN{$client}->{file}, $CONN{$client}->{timeout}, $CONN{$client}->{last_send}, $CONN{$client}->{last_recv}, $CONN{$client}->{retries});
        my $diffrecv = $now - $lastrecv;
        my $diffsend = $now - $lastsend;
        (defined $timeout && $timeout) or $timeout = 5;
        ($diffrecv > $timeout && $diffsend > $timeout) or next;
        if (! $retries) {
            $self->send_(pack ("n n a*", 5, 0, "Timeout\x00"));
            &INetSim::Log::SubLog("[$rhost:$rport] send: ERROR : " . $ERR{0} . " : 'Timeout'", $self->{servicename}, $$);
            &INetSim::Log::SubLog("[$rhost:$rport] disconnect (timeout)", $self->{servicename}, $$);
            &INetSim::Log::SubLog("[$rhost:$rport] stat: 0", $self->{servicename}, $$);
            if ($request eq "WRQ") {
                # delete incomplete files from virtual filesystem
                $self->_vfs_del_file($file);
            }
            delete $CONN{$client};
        }
        else {
            $CONN{$client}->{is_retry} = 1;
            $CONN{$client}->{last_block} = $CONN{$client}->{block};
            if ($request eq "RRQ") {
                $self->send_DATA($client);
            }
            elsif ($request eq "WRQ") {
                $self->send_ACK($client);
            }
        }
    }
}



sub RRQ {
    my ($self, $data) = @_;
    my $client = $self->{server}->{client};

    # already connected ?
    (! defined $CONN{$client}) or return;
    # check for invalid packet
    (defined $data && $data) or return;
    # get mode and file name
    my ($file, $mode, $options) = split(/\x00/, $data, 3);
    # check mode argument
    (defined $mode && $mode && $mode =~ /^(netascii|octet|mail)\z/i) or return;
    $mode = lc($mode);
    # register client
    my $rhost = $client->peerhost;
    my $rport = $client->peerport;
    $CONN{$client} = {  rhost		=> $rhost,
                        rport		=> $rport,
                        request		=> "RRQ",
                        file		=> undef,
                        mode		=> undef,
                        options		=> 0,
                        blksize		=> undef,
                        timeout		=> undef,
                        tsize		=> undef,
                        expected	=> undef,
                        block		=> 0,
                        bytes		=> 0,
                        last_send	=> 0,
                        last_recv	=> time(),
                        last_block	=> 0,
                        is_retry	=> 0,
                        retries		=> 2,
                        realfile	=> undef
                    };
    # i know, it's udp - but the first packet is like a connect :-)
    $self->slog_("connect");
    # check options if any
    my $opt = $self->check_options($options);
    # only for logging: replace non-printable characters in the file name with "."
    my $filtered = $file;
    $filtered =~ s/([^\x20-\x7e])/\./g;
    # log request
    if ($opt) {
        $self->slog_("recv: RRQ $filtered $mode (options: $opt)");
    }
    else {
        $self->slog_("recv: RRQ $filtered $mode (options: none)");
    }
    # option not accepted
    if (! defined $opt) {
        $self->send_ERROR(8, "Option or value not accepted");
        $self->slog_("disconnect");
        $self->slog_("stat: 0");
        delete $CONN{$client};
        return;
    }
    # mode "mail" is not yet implemented -> error
    if ($mode eq "mail") {
        $self->send_ERROR(0, "Mode 'mail' not implemented");
        $self->slog_("disconnect");
        $self->slog_("stat: 0");
        delete $CONN{$client};
        return;
    }
    $CONN{$client}->{mode} = $mode;
    # check file argument
    if (! defined $file || ! $file || $file !~ /^([\x20-\x7E]+)$/) {
        $self->send_ERROR(2, "Invalid file name");
        $self->slog_("disconnect");
        $self->slog_("stat: 0");
        delete $CONN{$client};
        return;
    }
    # check if file exists
    my $vfile = $self->_vfs_file_exists($file);
    if (! defined $vfile || ! $vfile) {
        $self->send_ERROR(1, "No such file");
        $self->slog_("disconnect");
        $self->slog_("stat: 0");
        delete $CONN{$client};
        return;
    }
    my ($flag, $type, $rpath) = split (/\|/, $VFS{"$vfile"});
    if (! defined $type || $type ne "f" || ! defined $rpath || ! -f $rpath || ! -r $rpath) {
        $self->send_ERROR(1, "File not found");
        $self->slog_("disconnect");
        $self->slog_("stat: 0");
        delete $CONN{$client};
        return;
    }
    $CONN{$client}->{file} = $file;
    $CONN{$client}->{realfile} = $rpath;
    if ($CONN{$client}->{options}) {
        # -> OACK -> ACK -> DATA
        $self->send_OACK();
    }
    else {
        # -> DATA
        $self->send_DATA();
    }
}



sub WRQ {
    my ($self, $data) = @_;
    my $client = $self->{server}->{client};

    # already connected ?
    (! defined $CONN{$client}) or return;
    # check for invalid packet
    (defined $data && $data) or return;
    # get mode and file name
    my ($file, $mode, $options) = split(/\x00/, $data, 3);
    # check mode argument
    (defined $mode && $mode && $mode =~ /^(netascii|octet|mail)\z/i) or return;
    $mode = lc($mode);
    # register client
    my $rhost = $client->peerhost;
    my $rport = $client->peerport;
    $CONN{$client} = {  rhost		=> $rhost,
                        rport		=> $rport,
                        request		=> "WRQ",
                        file		=> undef,
                        mode		=> undef,
                        options		=> 0,
                        blksize		=> undef,
                        timeout		=> undef,
                        tsize		=> undef,
                        expected	=> undef,
                        block		=> 0,
                        bytes		=> 0,
                        last_send	=> 0,
                        last_recv	=> time(),
                        last_block	=> 0,
                        is_retry	=> 0,
                        retries		=> 2,
                        realfile	=> undef
                    };
    # i know, it's udp - but the first packet is like a connect :-)
    $self->slog_("connect");
    # check options if any
    my $opt = $self->check_options($options);
    # only for logging: replace non-printable characters in the file name with "."
    my $filtered = $file;
    $filtered =~ s/([^\x20-\x7e])/\./g;
    # log request
    if ($opt) {
        $self->slog_("recv: WRQ $filtered $mode (options: $opt)");
    }
    else {
        $self->slog_("recv: WRQ $filtered $mode (options: none)");
    }
    # option not accepted
    if (! defined $opt) {
        $self->send_ERROR(8, "Option or value not accepted");
        $self->slog_("disconnect");
        $self->slog_("stat: 0");
        delete $CONN{$client};
        return;
    }
    # mode "mail" is not yet implemented -> error
    if ($mode eq "mail") {
        $self->send_ERROR(0, "Mode 'mail' not implemented");
        $self->slog_("disconnect");
        $self->slog_("stat: 0");
        delete $CONN{$client};
        return;
    }
    $CONN{$client}->{mode} = $mode;
    # check file argument
    if (! defined $file || ! $file || $file !~ /^([\x20-\x7E]+)$/) {
        $self->send_ERROR(2, "Invalid file name");
        $self->slog_("disconnect");
        $self->slog_("stat: 0");
        delete $CONN{$client};
        return;
    }
    # check if file already exists
    if (! $self->{allow_overwrite}) {
        my $vfile = $self->_vfs_file_exists($file);
        if (defined $vfile && $vfile) {
            $self->send_ERROR(6, "File already exists");
            $self->slog_("disconnect");
            $self->slog_("stat: 0");
            delete $CONN{$client};
            return;
        }
    }
    $CONN{$client}->{file} = $file;

    if ($CONN{$client}->{options}) {
        # -> OACK
        $self->send_OACK();
    }
    else {
        # -> ACK
        $self->send_ACK();
    }
}



sub send_OACK {
    my $self = shift;
    my $client = $self->{server}->{client};
    my $opt;
    my $log;

    (defined $CONN{$client}) or return;
    (defined $CONN{$client}->{options} && $CONN{$client}->{options}) or return;
    $CONN{$client}->{last_send} = time();
    if ($CONN{$client}->{request} eq "RRQ") {
        $CONN{$client}->{expected} = "ACK";
        if (defined $CONN{$client}->{tsize} && -f $CONN{$client}->{realfile}) {
            $CONN{$client}->{tsize} = -s $CONN{$client}->{realfile};
        }
    }
    elsif ($CONN{$client}->{request} eq "WRQ") {
        $CONN{$client}->{expected} = "DATA";
    }
    foreach (qw/blksize timeout tsize/) {
        (defined $CONN{$client}->{$_} && $CONN{$client}->{$_}) or next;
        $opt .= "$_\x00$CONN{$client}->{$_}\x00";
        $log .= "$_ $CONN{$client}->{$_} ";
    }
    $log =~ s/\s+$//;
    $self->slog_("send: OACK $log");
    $self->send_(pack ("n a*", 6, $opt));
}



sub DATA {
    my ($self, $raw) = @_;
    my $client = $self->{server}->{client};
    my $blocksize;

    # connected ?
    (defined $client && defined $CONN{$client}) or return;
    # check for invalid packet
    (defined $raw && $raw) or return;
    # was the initial packet a WRQ and therefore we expect a data packet ?
    ($CONN{$client}->{request} eq "WRQ" && $CONN{$client}->{expected} eq "DATA") or return;
    # get block number and data
    my ($block, $data) = unpack ("n a*", $raw);
    # block number should not be zero
    if (! $block) {
        $self->send_ERROR(4, "Invalid block number");
        $self->slog_("disconnect");
        $self->slog_("stat: 0");
        delete $CONN{$client};
        return;
    }
    $CONN{$client}->{last_recv} = time();
    # get length
    my $length = length($data);
    # check for valid block number
    ($block == int($CONN{$client}->{block} + 1)) or return;
    # set block size
    if (defined $CONN{$client}->{blksize} && $CONN{$client}->{blksize}) {
        $blocksize = $CONN{$client}->{blksize};
        # check for stupid clients (atftp) and correct the blocksize
        if ($block == 1 && $length > $CONN{$client}->{blksize}) {
            $CONN{$client}->{blksize} = $length;
            $self->slog_("w00t: The client lies about his block size, adjusted to $length :-/");
        }
    }
    else {
        $blocksize = 512;
    }
    # creating file, if block = 1
    if ($block == 1) {
        srand(time() ^($$ + ($$ <<15)));
        my $sha = Digest::SHA->new();
        $sha->add(int(rand(100000000)));
        $sha->add(time());
        $CONN{$client}->{realfile} = $self->{upload_dir} . "/" . $sha->hexdigest;
    }
    my $rpath = $CONN{$client}->{realfile};

    # try to open
    if (! open (DAT, ">> $rpath")) {
        $self->send_ERROR(0, "Unable to write");
        $self->slog_("disconnect");
        $self->slog_("stat: 0");
        delete $CONN{$client};
        return;
    }
    chmod 0660, $rpath;
    binmode (DAT);
    if ($block) {
        print DAT $data;
    }
    close DAT;
    # save the file in virtual file system
    my $result = $self->_vfs_add_file($CONN{$client}->{file}, $CONN{$client}->{realfile});
    $CONN{$client}->{block} = $block;
    $CONN{$client}->{bytes} += $length;
    $self->send_ACK();
    if ($length < $blocksize) {
        $self->slog_("recv: DATA (blocks: $block, block size: $blocksize bytes, file size: $CONN{$client}->{bytes} bytes)");
        $self->slog_("info: Stored $CONN{$client}->{bytes} bytes of data to: $rpath, original file name: $CONN{$client}->{file}");
        $self->slog_("disconnect");
        $self->slog_("stat: 1 request=write mode=$CONN{$client}->{mode} name=$CONN{$client}->{file}");
        delete $CONN{$client};
    }
}



sub ACK {
    my ($self, $data) = @_;
    my $client = $self->{server}->{client};

    (defined $CONN{$client}) or return;
    (defined $data && $data) or return;
    my $block = unpack ("n", $data);
    (defined $block) or return;
    ($CONN{$client}->{request} eq "RRQ" && $CONN{$client}->{block} == $block) or return;
    if ($CONN{$client}->{expected} eq "ACK") {
        if ($block == 0) {
            $self->slog_("recv: ACK block $block");
        }
        $self->send_DATA();
    }
    elsif ($CONN{$client}->{expected} eq "LASTACK") {
        $self->slog_("recv: ACK block $block");
        $self->slog_("disconnect");
        $self->slog_("stat: 1 request=read mode=$CONN{$client}->{mode} name=$CONN{$client}->{file}");
        delete $CONN{$client};
    }
}



sub ERROR {
    my ($self, $data) = @_;
    my $client = $self->{server}->{client};

    (defined $CONN{$client}) or return;
    (defined $data && $data) or return;
    my ($code, $message) = unpack ("n a*", $data);
    (defined $code && defined $message && $message) or return;
    ($code >= 0 && $code <= 8) or return;
    $message =~ s/\x00$//;
    $message =~ s/([^\x20-\x7e])/\./g;
    $self->slog_("recv: ERROR : $ERR{$code} : '$message'");
    $self->slog_("disconnect");
    $self->slog_("stat: 0");
    if ($CONN{$client}->{request} eq "WRQ") {
        # delete incomplete file from virtual filesystem
        $self->_vfs_del_file($CONN{$client}->{file});
    }
    delete $CONN{$client};
}



sub send_DATA {
    my ($self, $client) = @_;
    (defined $client && $client) or $client = $self->{server}->{client};
    my $blocksize;

    (defined $CONN{$client}) or return;
    my $rpath = $CONN{$client}->{realfile};
    my $block;
    if ($CONN{$client}->{is_retry}) {
        $block = $CONN{$client}->{last_block};
        $CONN{$client}->{is_retry} = 0;
        $CONN{$client}->{retries}--;
    }
    else {
        $block = $CONN{$client}->{block} + 1;
        $CONN{$client}->{last_block} = $block;
    }
    # set block size
    if (defined $CONN{$client}->{blksize} && $CONN{$client}->{blksize}) {
        $blocksize = $CONN{$client}->{blksize};
    }
    else {
        $blocksize = 512;
    }
    my $size = -s $rpath;
    my $offset = ($blocksize * ($block - 1));
    if (! open(DAT, "$rpath")) {
        # should not happen
        $self->send_ERROR(0, "Internal server error");
        $self->slog_("disconnect");
        $self->slog_("stat: 0");
        delete $CONN{$client};
        return;
    }
    binmode (DAT);
    seek(DAT, $offset , 0);
    read(DAT, my $data, $blocksize);
    close DAT;
    my $length = length($data);
    if ($block == 1) {
        $self->slog_("info: Sending file: $rpath");
    }
    if ($length == $blocksize) {
        $CONN{$client}->{expected} = "ACK";
    }
    else {
        $CONN{$client}->{expected} = "LASTACK";
        $self->slog_("send: DATA (blocks: $block, block size: $blocksize bytes, file size: $size bytes)");
    }
    $CONN{$client}->{block} = $block;
    $CONN{$client}->{last_send} = time();
    $self->send_(pack ("n n a*", 3, $block, $data));
}



sub send_ACK {
    my ($self, $client) = @_;
    (defined $client && $client) or $client = $self->{server}->{client};

    (defined $CONN{$client}) or return;
    my $block;
    if ($CONN{$client}->{is_retry}) {
        $block = $CONN{$client}->{last_block};
        $CONN{$client}->{is_retry} = 0;
        $CONN{$client}->{retries}--;
    }
    else {
        $block = $CONN{$client}->{block};
        $CONN{$client}->{last_block} = $block;
    }
    $CONN{$client}->{last_send} = time();
    if ($block == 0) {
        $CONN{$client}->{expected} = "DATA";
        $self->slog_("send: ACK block 0");
    }
    $self->send_(pack ("n n", 4, $block));
}



sub send_ERROR {
    my ($self, $code, $msg, $client) = @_;
    (defined $client && $client) or $client = $self->{server}->{client};

    (defined $client) or return;
    (defined $code) or $code = 0;
    (defined $msg) or $msg = "unknown error";
    $self->slog_("send: ERROR : " . $ERR{$code} . " : '$msg'", $client);
    $self->send_(pack ("n n a*", 5, $code, $msg . "\x00"));
}



sub check_options {
    my ($self, $options) = @_;
    my $client = $self->{server}->{client};
    my ($option, $value);
    my ($min, $max);
    my $given = "";

    (defined $options && $options) or return 0;
    my @opt = split(/\x00/, $options);
    while (1) {
        last if (@opt <= 1);
        $option = shift(@opt);
        $value = shift(@opt);
        (defined $option && $option && $option =~ /^(blksize|timeout|tsize|multicast)$/i) or next;
        (defined $value && ((length($value) && $value =~ /^\d+$/) || $option eq "multicast")) or next;
        $option = lc($option);
        $given .= "$option=$value ";
        ($self->{options}) or next;
        if ($option eq "blksize" && defined $TFTP_OPT{blksize}) {
            ($value >= 8 && $value <= 65464) or next;
            ($min, $max) = split(/\s+/, $TFTP_OPT{blksize});
            # if block size defined, but smaller than client value -> set server value
            if ($value > $max) {
                $CONN{$client}->{blksize} = $TFTP_OPT{blksize};
            }
            # do not accept values less than minimum value
            elsif ($value < $min) {
                $CONN{$client}->{blksize} = undef;
            }
            # ...else set the client value
            else {
                $CONN{$client}->{blksize} = $value;
            }
        }
        elsif ($option eq "timeout" && defined $TFTP_OPT{timeout}) {
            ($value >= 1 && $value <= 255) or next;
            ($min, $max) = split(/\s+/, $TFTP_OPT{timeout});
            # do not accept values outside our range
            if ($value > $max || $value < $min) {
                $CONN{$client}->{timeout} = undef;
            }
            # ok, set client value
            else {
                $CONN{$client}->{timeout} = $value;
            }
        }
        elsif ($option eq "tsize" && defined $TFTP_OPT{tsize}) {
            if ($CONN{$client}->{request} eq "RRQ" && $value == 0) {
                $CONN{$client}->{tsize} = 0;
            }
            elsif ($CONN{$client}->{request} eq "WRQ") {
                # requested transfer size to big
                if ($value > $TFTP_OPT{tsize}) {
                    return undef;
                }
                else {
                    $CONN{$client}->{tsize} = $value;
                }
            }
        }
    }
    (! defined $CONN{$client}->{blksize} && ! defined $CONN{$client}->{timeout} && ! defined $CONN{$client}->{tsize}) or $CONN{$client}->{options} = 1;
    $given =~ s/\s+$//;
    return $given;
}


sub send_ {
    my ($self, $msg) = @_;
    my $sock = $self->{server}->{socket};

    (defined $msg) or return;
    $sock->send($msg);
}



sub slog_ {
    my ($self, $msg, $sock) = @_;
    (defined $sock && $sock) or $sock = $self->{server}->{client};
    my $rhost = $sock->peerhost;
    my $rport = $sock->peerport;

    (defined $msg) or return;
    $msg =~ s/[\r\n]*//;
    &INetSim::Log::SubLog("[$rhost:$rport] $msg", $self->{servicename}, $$);
}



sub dlog_ {
    my ($self, $msg, $sock) = @_;
    (defined $sock && $sock) or $sock = $self->{server}->{client};
    my $rhost = $sock->peerhost;
    my $rport = $sock->peerport;

    (defined $msg) or return;
    $msg =~ s/[\r\n]*//;
    &INetSim::Log::DebugLog("[$rhost:$rport] $msg", $self->{servicename}, $$);
}






### BEGIN: VFS stuff

# key = file, value = flag|dirORfile|realpath


sub init_VFS {
    my $self = shift;
    my @dirs;
    my $name;
    my $vname;
    my $mtime;
    my $dir;

    # read the session file, if exist
    $self->_read_vfs_changes;

#    # rebuild only if empty
#    return if (keys (%VFS) >= 1);

    # first, add '/' to the filesystem
    $mtime = int (&INetSim::FakeTime::get_faketime() - rand(7200));
    $VFS{'/'} = "1|d|";
    $self->{current_dir} = "/";
    # now walk through the document root and add directories and files
    push (@dirs, $self->{document_root});	# push document root to the "stack"
    while (@dirs) {
        $dir = pop (@dirs);
        if (opendir (DIR, $dir)) {
            while (defined ($name = readdir (DIR))) {
                next if $name eq '.';
                next if $name eq '..';
                $vname = "$dir/$name";
                $vname =~ s/^$self->{document_root}//;	# chr00t ;-)
                $mtime = int (&INetSim::FakeTime::get_faketime() - rand(3600));
                if (-d "$dir/$name") {
                    push (@dirs, "$dir/$name");
                    $self->_vfs_add_dir($vname, "$dir/$name");
                }
                elsif (-f "$dir/$name") {
                    $self->_vfs_add_file($vname, "$dir/$name");
                }
            }
            closedir DIR;
        }
    }
}


sub _vfs_add_file {
    my $self = shift;
    my $vpath = shift;	# virtual path
    my $rpath = shift;	# real path
    my $dir;

    if (defined ($vpath) && defined ($rpath)) {
        if (-f $rpath && -r $rpath) {
            # add base directory of the file
            $self->_vfs_add_dir($self->_dirname($vpath));
            # check for absolute path
            if ($vpath !~ /^\//) {
                # build absolute virtual path name
                $vpath = "$self->{current_dir}/$vpath";
            }
            # filter virtual path name
            $vpath = $self->_filter_pathstring($vpath);
            # add file to vfs (if not empty)
            if (defined ($vpath) && $vpath ne "" && $vpath ne "/") {
                $VFS{"$vpath"} = "1|f|$rpath";
                return ($vpath);
            }
        }
    }
    return undef;
}


sub _vfs_del_file {
    my $self = shift;
    my $vpath = shift;  # virtual path

    if (defined ($vpath)) {
        # check for absolute path
        if ($vpath !~ /^\//) {
            # build absolute virtual path name
            $vpath = "$self->{current_dir}/$vpath";
        }
        # filter virtual path name
        $vpath = $self->_filter_pathstring($vpath);
        if (defined ($vpath) && $vpath ne "" && defined ($VFS{"$vpath"}) && $VFS{"$vpath"} !~ /^d/) {
            delete $VFS{"$vpath"};
            return ($vpath);
        }
    }
    return undef;
}


sub _vfs_file_exists {
    my $self = shift;
    my $vpath = shift;	# virtual path

    if (defined ($vpath)) {
        # check for absolute path
        if ($vpath !~ /^\//) {
            # build absolute virtual path name
            $vpath = "$self->{current_dir}/$vpath";
        }
        # filter virtual path name
        $vpath = $self->_filter_pathstring($vpath);
        if (defined ($vpath) && $vpath ne "" && defined ($VFS{"$vpath"}) && $VFS{"$vpath"} !~ /^d/) {
            return ($vpath);
        }
    }
    return undef;
}


sub _vfs_add_dir {
    my $self = shift;
    my $vpath = shift;	# virtual path

    if (defined ($vpath)) {
        # check for absolute path
        if ($vpath !~ /^\//) {
            # build absolute virtual path name
            $vpath = "$self->{current_dir}/$vpath";
        }
        # filter virtual path name
        $vpath = $self->_filter_pathstring($vpath);
        # add directory to vfs (if not empty)
        if (defined ($vpath) && $vpath ne "" && $vpath ne "/") {
            $VFS{"$vpath"} = "1|d|";
            return ($vpath);
        }
    }
    return undef;
}


sub _vfs_dir_exists {
    my $self = shift;
    my $vpath = shift;	# virtual path

    if (defined ($vpath)) {
        # check for absolute path
        if ($vpath !~ /^\//) {
            # build absolute virtual path name
            $vpath = "$self->{current_dir}/$vpath";
        }
        # filter virtual path name
        $vpath = $self->_filter_pathstring($vpath);
        if (defined ($vpath) && $vpath ne "" && defined ($VFS{"$vpath"}) && $VFS{"$vpath"} =~ /^d/) {
            return ($vpath);
        }
    }
    return undef;
}


sub _read_vfs_changes {
    my $self = shift;
    my %seen = ();
    my @raw;
    my $key;

    if (open (SES, "$self->{sessionfile}")) {
	chomp(@raw = <SES>);
	close SES;
	foreach (grep { ! $seen{ $_ }++ } @raw) {
	    my ($content, $vpath) = split (/\!/, $_, 2);
	    chomp($vpath);
	    $VFS{"$vpath"} = $content;
	}
    }
    return;
}


sub _save_vfs_changes {
    my $self = shift;
    my %seen = ();
    my @raw;
    my $key;

    while () {
        if (open (SES, "> $self->{sessionfile}")) {
            chmod 0660, $self->{sessionfile};
            if (flock(SES, LOCK_EX)) {
	        foreach $key (keys %VFS) {
		    print SES "$VFS{$key}!$key\n";
	        }
		close SES;
		return 1;
	    }
	    close SES;
        }
	sleep 1;
    }
    return;
}


sub _filter_pathstring {
    my $self = shift;
    my $path = shift;
    my @parts;

    if (defined ($path) && $path ne "") {
        @parts = split(/\/+/, $path);
        @parts = ('', '') unless @parts;
        unshift (@parts, '') unless @parts > 1;
        for (my $i = 1; $i < @parts;) {
            if ($parts[$i] eq '.') {
                splice (@parts, $i, 1);
            }
            elsif ($parts[$i] eq '..' && $i == 1) {
                splice (@parts, $i, 1);
            }
            elsif ($parts[$i] eq '..') {
                splice (@parts, ($i - 1), 2);
                $i--;
            }
            else {
                $i++;
            }
        }
        unshift (@parts, '') unless @parts > 1;
        return (join ('/', @parts));
    }
    return undef;
}


sub _basename {
    my $self = shift;
    my $path = shift;
    my @parts;

    if (defined ($path) && $path ne "") {
	if ($path eq '/') {
	    return '/';
	} else {
	    @parts = split (m{/}, $path);
	    return (pop @parts);
	}
    }
    return undef;
}


sub _dirname {
    my $self = shift;
    my $path = shift;

    if (defined ($path) && $path ne "") {
	if ($path eq '/') {
		return '/';
	} else {
		my @parts = split (m{/}, $path);
		pop @parts;
		push (@parts, '') if @parts == 1;
		return (join ('/', @parts));
	}
    }
    return undef;
}



### BEGIN: Server stuff



sub server_close {
    my $self = shift;

    $self->{server}->{socket}->close();
    exit 0;
}



sub new {
  my $class = shift || die "Missing class";
  my $args  = @_ == 1 ? shift : {@_};
  my $self  = bless {server => { %$args }}, $class;
  return $self;
}



sub bind {
    my $self = shift;

    # evil untaint
    $self->{server}->{host} =~ /(.*)/;
    $self->{server}->{host} = $1;

    # bind to socket
    $self->{server}->{socket} = new IO::Socket::INET( LocalAddr	=> $self->{server}->{host},
                                                      LocalPort	=> $self->{server}->{port},
                                                      Proto	=> $self->{server}->{proto},
                                                      Type	=> $self->{server}->{type}
                                                     );
    (defined $self->{server}->{socket}) or $self->fatal_hook("$!");
    # add socket to select
    $self->{server}->{select} = new IO::Select($self->{server}->{socket});
    (defined $self->{server}->{select}) or $self->fatal_hook("$!");

    # drop root privileges
    my $uid = getpwnam($self->{server}->{user});
    my $gid = getgrnam($self->{server}->{group});
    # group
    POSIX::setgid($gid);
    my $newgid = POSIX::getgid();
    if ($newgid != $gid) {
        &INetSim::Log::MainLog("failed! (Cannot switch group)", $self->{servicename});
        $self->server_close;
    }
    # user
    POSIX::setuid($uid);
    if ($< != $uid || $> != $uid) {
        $< = $> = $uid; # try again - reportedly needed by some Perl 5.8.0 Linux systems
        if ($< != $uid) {
            &INetSim::Log::MainLog("failed! (Cannot switch user)", $self->{servicename});
            $self->server_close;
        }
    }

    # ignore SIG_INT, SIG_PIPE and SIG_QUIT
    $SIG{'INT'} = $SIG{'PIPE'} = $SIG{'QUIT'} = 'IGNORE';
    # only "listen" for SIG_TERM from parent process
    $SIG{'TERM'} = sub { $self->pre_server_close_hook; $self->server_close; };
}



sub run {
    my $self = ref($_[0]) ? shift() : shift->new;

    # configure this service
    $self->configure_hook;
    # open the socket and drop privilegies (set user/group)
    $self->bind;
    # just for compatibility with net::server
    $self->pre_loop_hook;
    # standard loop for: receive->process_request->check_timeout
    $self->loop;
    # just for compatibility with net::server
    $self->pre_server_close_hook;
    # shutdown socket and exit
    $self->server_close;
}


sub loop {
    my $self = shift;
    my $socket = $self->{server}->{socket};
    my $select = $self->{server}->{select};
    my $client;
    my $bytes;
    my $buffer;
    my $rhost;
    my $rport;

    while (1) {
        my @can_read = $select->can_read(0.1);
        $self->{number_of_clients} = int($select->count());
        foreach $client (@can_read) {
            $bytes = $client->recv($buffer, 65468);
            (defined $bytes) or next;
            $self->{server}->{client} = $client;
            $self->{server}->{data} = $buffer;
            $self->process_request();
        }
        my @can_write = $select->can_write(0.1);
        $self->{number_of_clients} = int($select->count());
        foreach $client (@can_write) {
            $self->{server}->{client} = $client;
            $self->check_timeout();
        }
    }
}



sub register_options {
    my $self = shift;
    my %option;

    if ($self->{options}) {
        %option = &INetSim::Config::getConfigHash("TFTP_Options");
        foreach my $key (keys %option) {
            if (defined ($OPT_AVAIL{$key}) && $OPT_AVAIL{$key}) {
                if (! defined ($TFTP_OPT{$key})) {
                    $option{$key} =~ s/[\s]+$//;
                    # parameters are allowed
                    if ($OPT_AVAIL{$key} == 2) {
                        $TFTP_OPT{$key} = $option{$key};
                    }
                    # parameters are not allowed
                    else {
                        $TFTP_OPT{$key} = "";
                    }
                }
            }
        }
        # resolve possible dependencies below...
        #
        # check range for blocksize parameters
        if (defined $TFTP_OPT{blksize}) {
            # nothing defined, set maximum range
            if (! $TFTP_OPT{blksize}) {
                $TFTP_OPT{blksize} = "8 65464";
            }
            else {
                # some values defined, check that
                my ($min, $max) = split(/[\s\t]+/, $TFTP_OPT{blksize}, 2);
                # invalid ? set to minimum value
                if (! defined $min || ! $min || $min !~ /^\d+$/ || $min < 8 || $min > 65464) {
                    $min = 8;
                }
                # invalid ? set to maximum
                if (! defined $max || ! $max || $max !~ /^\d+$/ || $max < 8 || $max > 65464) {
                    $max = 65464;
                }
                # switch min & max, if min greater max
                if ($min > $max) {
                    $TFTP_OPT{blksize} = "$max $min";
                }
                else {
                    $TFTP_OPT{blksize} = "$min $max";
                }
            }
        }
        # check range for timeout
        if (defined $TFTP_OPT{timeout}) {
            # nothing defined -> maximum range
            if (! $TFTP_OPT{timeout}) {
                $TFTP_OPT{timeout} = "1 255";
            }
            else {
                # some values defined...
                my ($min, $max) = split(/[\s\t]+/, $TFTP_OPT{timeout}, 2);
                # invalid ? set to minimum
                if (! defined $min || ! $min || $min !~ /^\d+$/ || $min < 1 || $min > 255) {
                    $min = 1;
                }
                # invalid ? set to maximum
                if (! defined $max || ! $max || $max !~ /^\d+$/ || $max < 1 || $max > 255) {
                    $max = 255;
                }
                # switch min & max, if min greater max
                if ($min > $max) {
                    $TFTP_OPT{timeout} = "$max $min";
                }
                else {
                    $TFTP_OPT{timeout} = "$min $max";
                }
            }
        }
        # check maximum transfer size
        if (defined $TFTP_OPT{tsize}) {
            # nothing defined -> maximum tsize = 10MB
            if (! $TFTP_OPT{tsize}) {
                $TFTP_OPT{tsize} = 10485760;
            }
            else {
                # defined value invalid ? then set to default
                if ($TFTP_OPT{tsize} !~ /^\d+$/ || $TFTP_OPT{tsize} < 1 || $TFTP_OPT{tsize} > 1073741824) {
                    $TFTP_OPT{tsize} = 10485760;
                }
            }
        }
    }
}




sub error_exit {
    my ($self, $sock, $msg) = @_;
    my $rhost = $sock->peerhost;
    my $rport = $sock->peerport;

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
# Version 0.59  (2009-12-18) me
# - do not log 'service stop' twice
#
# Version 0.58  (2009-10-13) me
# - added function register_options()
# - added pre_server_close_hook() to signal handler
# - enhanced support for 'timeout' and 'tsize' option
# - fixed a typo in check_options()
# - some small bugfixes
#
# Version 0.57  (2009-10-12) me
# - added configuration variables 'TFTP_UploadDir', 'TFTP_AllowOverwrite'
#   and 'TFTP_EnableOptions'
# - added configuration hash 'TFTP_Options'
#
# Version 0.56  (2009-10-11) me
# - added support for 'blksize' option (RFC 2348)
# - added function check_timeout(), therefore added code to
#   repeat unanswered packets when the timeout occurs
# - added support for 'timeout' and 'tsize' options (RFC 2349)
# - small code cleanups
#
# Version 0.55  (2009-10-10) me
# - removed use of Net::Server and IPC::Shareable
# - added general routines to handle udp packets
# - complete rewrite (oo-style)
# - changed all data types in pack/unpack
# - added the virtual filesystem from FTP module (slightly downsized),
#   so the old index and data files are no longer needed
# - added general support for TFTP options (RFC 2347),
#   therefore added a function called send_OACK()
# - removed a bunch of unnecessary variables
#
# Version 0.54  (2009-10-09) me
# - prepared rewrite for work with IO::Select instead of Net::Server
# - playing around with IO::Select and learned some things about
#   his behavior while using the udp protocol
#
# Version 0.53  (2008-08-27) me
# - added logging of process id
#
# Version 0.52  (2007-12-31) th
# - change process name
#
# Version 0.51  (2007-09-03) me
# - create uploads.dat and uploads.idx if they do not exist
#
# Version 0.50  (2007-05-28) me
# - changed DATA-section to work with new configuration option
#   "TFTP_EnableUpload"
#
# Version 0.49  (2007-05-26) me
# - changed WRQ-section to work with new configuration option
#   "TFTP_EnableUpload"
#
# Version 0.48  (2007-04-26) th
# - use getConfigParameter
#
# Version 0.47  (2007-04-24) th
# - changed Shareable-GLUE to "TFTP"
#
# Version 0.46  (2007-04-24) th
# - added function error_exit()
# - replaced die() calls with error_exit()
#
# Version 0.45  (2007-04-21) me
# - added logging of status for use with &INetSim::Report::GenReport()
#
# Version 0.44  (2007-04-19) me
# - added check for minimal packet length of 4 bytes
# - fixed a typo in configure hook
#
# Version 0.43  (2007-04-18) me
# - logging of every DATA packet removed
#
# Version 0.42  (2007-04-05) th
# - changed check for MaxChilds, BindAddress, RunAsUser and
#   RunAsGroup
#
# Version 0.41  (2007-04-02) me
# - fix with handling of last ack
# - fixed strange behavior, if tftp is under load (maybe)
#
# Version 0.4   (2007-03-31) me
# - complete rewrite *argh*
# - small bugfixes with variables (range check)
# - added a filter for path- and filenames (that keeps
#   subdirectorys)
# - ugly "brainbug" fixed: a very special case - lost bytes,
#   if [ filesize % 512 == 0 ]
# - some tests with netcat performed - yeah, looks good :-)
# - ToDo: FakeMode
# - ToDo: use of temporary files should be removed
#
# Version 0.3   (2007-03-30) me
# - rewrote module to use INetSim::GenericServer
# - temporary files now uses /tmp/, because we can't write a
#   $BASEDIR.$somefile as "nobody:nogroup"  :-(
#   (today is a good day to die, i think !!)
#
# Version 0.2   (2007-03-30) me
# -  small bugfixes with variables
#
# Version 0.1   (2007-03-29) me
# - initial version - it works !!! (standalone)
#
#############################################################
