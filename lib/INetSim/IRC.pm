# -*- perl -*-
#
# INetSim::IRC - A fake IRC server
#
# RFC 1459 - Internet Relay Chat Protocol
#
# (c)2009-2010 Matthias Eckert, Thomas Hungenberg
#
# Version 0.10 (2010-04-19)
#
# For history/changelog see bottom of this file.
#
#############################################################

package INetSim::IRC;

use strict;
use warnings;
use POSIX;
use IO::Socket;
use IO::Select;


my %CONN;
my %NICK;
my %USER;
my %HOST;
my %CHAN;



sub loop {
    my $self = shift;
    my $socket = $self->{server}->{socket};
    my $select = $self->{server}->{select};
    my $client;

    while (1) {
        my @can_read = $select->can_read(0.01);
        $self->{number_of_clients} = int($select->count());
        foreach $client (@can_read) {
            if ($client == $socket) {
                $self->_accept;
                next;
            }
            $self->{server}->{client} = $client;
            $self->process_request;
        }
        my @can_write = $select->can_write(0.01);
        $self->{number_of_clients} = int($select->count());
        foreach $client (@can_write) {
            $self->{server}->{client} = $client;
            #$self->check_timeout();
        }
    }
}



sub send_initial_response {
    my $self = shift;
    my $client = $self->{server}->{client};

    my $now = &INetSim::FakeTime::get_faketime();
    $CONN{$client}->{connected} = $now;
    $CONN{$client}->{last_send} = $now;
    $CONN{$client}->{host} = $client->peerhost;
    $CONN{$client}->{port} = $client->peerport;
    $self->send_("NOTICE AUTH :*** Welcome to $self->{hostname}");
    $self->send_("NOTICE AUTH :*** Looking up your hostname");
    $self->send_("NOTICE AUTH :*** Checking Ident");
    $self->send_("NOTICE AUTH :*** No ident response");
    $self->send_("NOTICE AUTH :*** Found your hostname");
}



sub _accept {
    my $self = shift;

    # accept the new connection
    my $client = $self->{server}->{socket}->accept;
    (defined $client) or return 0;
    ($client->connected) or return 0;
    $self->{server}->{client} = $client;

    # add the new handle to IO::Select
    $self->{server}->{select}->add($client);
    if ($self->{server}->{select}->exists($client)) {
        $self->slog_("connect");
        $self->send_initial_response();
        return 1;
    }
    else {
        $self->slog_("connect");
        if ($self->{number_of_clients} >= $self->{maxchilds}) {
            $self->send_("ERROR :Closing Link: " . $client->peerhost . " (Maximum number of connections ($self->{maxchilds}) exceeded)");
        }
        else {
            $self->send_("ERROR :Closing Link: " . $client->peerhost . " (Internal server error)");
        }
        $self->slog_("disconnect");
        $client->close;
        return 0;
    }
}


sub register_connection {
    my $self = shift;
    my $client = $self->{server}->{client};
    my $rhost = $client->peerhost;
    my $rport = $client->peerport;

    $CONN{$client} = {  connected	=> 0,
                        host		=> undef,
                        port		=> undef,
                        ssl		=> undef,
                        last_recv	=> 0,
                        last_send	=> undef,
                        last_ping_send	=> 0,
                        last_pong_recv	=> 0,
                        retries		=> 2,
                        registered	=> 0,
                        pass		=> undef,
                        user		=> undef,
                        nick		=> undef,
                        realname	=> undef,
                        channels	=> undef,
                        modes		=> undef
                    };
}


sub process_request {
    my $self = shift;
    my $client = $self->{server}->{client};
    my $rhost = $client->peerhost;
    my $rport = $client->peerport;
#    my $registered = $CONN{$client}->{registered};
#    my $user = $CONN{$client}->{user};
#    my $nick = $CONN{$client}->{nick};

    my $line = <$client>;
    if (!defined $line) {
        $self->QUIT;
        return;
    }
    $line =~ s/[\r\n]+$//;
    ($line) or return;
    $self->slog_("recv: $line");
    # update timestamp
    $CONN{$client}->{last_recv} = &INetSim::FakeTime::get_faketime();
    # process request below...
    my ($user, $nick, $host, $command, $params) = $self->split_messageparts($line);
    (defined $command && $command) or return;
    #
    if ($command =~ /^PASS$/i) {
        $self->PASS($user, $nick, $host, $params);
    }
    elsif ($command =~ /^NICK$/i) {
        $self->NICK($user, $nick, $host, $params);
    }
    elsif ($command =~ /^USER$/i) {
        $self->USER($user, $nick, $host, $params);
    }
#    elsif ($command =~ /^SERVER$/i) {
#        $self->SERVER($user, $nick, $host, $params);
#    }
#    elsif ($command =~ /^OPER$/i) {
#        $self->OPER($user, $nick, $host, $params);
#    }
    elsif ($command =~ /^QUIT$/i) {
        $self->QUIT($user, $nick, $host, $params);
    }
#    elsif ($command =~ /^SQUIT$/i) {
#        $self->SQUIT($user, $nick, $host, $params);
#    }
    elsif ($command =~ /^JOIN$/i) {
        $self->JOIN($user, $nick, $host, $params);
    }
    elsif ($command =~ /^PART$/i) {
        $self->PART($user, $nick, $host, $params);
    }
    elsif ($command =~ /^MODE$/i) {
        $self->MODE($user, $nick, $host, $params);
    }
#    elsif ($command =~ /^TOPIC$/i) {
#        $self->TOPIC($user, $nick, $host, $params);
#    }
#    elsif ($command =~ /^NAMES$/i) {
#        $self->NAMES($user, $nick, $host, $params);
#    }
#    elsif ($command =~ /^LIST$/i) {
#        $self->LIST($user, $nick, $host, $params);
#    }
#    elsif ($command =~ /^INVITE$/i) {
#        $self->INVITE($user, $nick, $host, $params);
#    }
#    elsif ($command =~ /^KICK$/i) {
#        $self->KICK($user, $nick, $host, $params);
#    }
#    elsif ($command =~ /^VERSION$/i) {
#        $self->VERSION($user, $nick, $host, $params);
#    }
#    elsif ($command =~ /^STATS$/i) {
#        $self->STATS($user, $nick, $host, $params);
#    }
#    elsif ($command =~ /^LINKS$/i) {
#        $self->LINKS($user, $nick, $host, $params);
#    }
#    elsif ($command =~ /^TIME$/i) {
#        $self->TIME($user, $nick, $host, $params);
#    }
#    elsif ($command =~ /^CONNECT$/i) {
#        $self->CONNECT($user, $nick, $host, $params);
#    }
#    elsif ($command =~ /^TRACE$/i) {
#        $self->TRACE($user, $nick, $host, $params);
#    }
#    elsif ($command =~ /^ADMIN$/i) {
#        $self->ADMIN($user, $nick, $host, $params);
#    }
#    elsif ($command =~ /^INFO$/i) {
#        $self->INFO($user, $nick, $host, $params);
#    }
    elsif ($command =~ /^PRIVMSG$/i) {
#        $self->PRIVMSG($user, $nick, $host, $params);
        if ($CONN{$client}->{registered}) {
            $self->broadcast(":" . $CONN{$client}->{nick} . "!" . $CONN{$client}->{user} . "\@" . $CONN{$client}->{host} . " PRIVMSG $params");
#print STDERR ":" . $CONN{$client}->{nick} . "!" . $CONN{$client}->{user} . "\@" . $CONN{$client}->{host} . " PRIVMSG $params\n";
        }
    }
#    elsif ($command =~ /^NOTICE$/i) {
#        $self->NOTICE($user, $nick, $host, $params);
#    }
#    elsif ($command =~ /^WHO$/i) {
#        $self->WHO($user, $nick, $host, $params);
#    }
#    elsif ($command =~ /^WHOIS$/i) {
#        $self->WHOIS($user, $nick, $host, $params);
#    }
#    elsif ($command =~ /^WHOWAS$/i) {
#        $self->WHOWAS($user, $nick, $host, $params);
#    }
#    elsif ($command =~ /^KILL$/i) {
#        $self->KILL($user, $nick, $host, $params);
#    }
    elsif ($command =~ /^PING$/i) {
        $self->PING($user, $nick, $host, $params);
    }
    elsif ($command =~ /^PONG$/i) {
        $self->PONG($user, $nick, $host, $params);
    }
#    elsif ($command =~ /^ERROR$/i) {
#        $self->ERROR($user, $nick, $host, $params);
#    }
    # OPTIONALS
#    elsif ($command =~ /^AWAY$/i) {
#        $self->AWAY($user, $nick, $host, $params);
#    }
#    elsif ($command =~ /^REHASH$/i) {
#        $self->REHASH($user, $nick, $host, $params);
#    }
#    elsif ($command =~ /^RESTART$/i) {
#        $self->RESTART($user, $nick, $host, $params);
#    }
#    elsif ($command =~ /^SUMMON$/i) {
#        $self->SUMMON($user, $nick, $host, $params);
#    }
#    elsif ($command =~ /^USERS$/i) {
#        $self->USERS($user, $nick, $host, $params);
#    }
#    elsif ($command =~ /^WALLOPS$/i) {
#        $self->WALLOPS($user, $nick, $host, $params);
#    }
#    elsif ($command =~ /^USERHOST$/i) {
#        $self->USERHOST($user, $nick, $host, $params);
#    }
#    elsif ($command =~ /^ISON$/i) {
#        $self->ISON($user, $nick, $host, $params);
#    }
#    else {
#    # nick!user@host
#        if ($CONN{$client}->{registered}) {
#            $self->broadcast(":$nick!$user\@$host PRIVMSG #CHAN :$line");
#        }
#    }
}


sub split_messageparts {
    my ($self, $raw) = @_;
    my $client = $self->{server}->{client};
    my $prefix;
    my ($user, $nick, $host, $command, $params);
    my $dummy;

    (defined $raw && $raw) or return undef;
    $raw =~ s/[^\x20-\x7E\r\n\t]//g;
    $raw =~ s/^[\s\t]+//;
    if ($raw =~ /^:/) {
        ($prefix, $command, $params) = split (/[\s\t]+/, $raw, 3);
        if (defined $prefix && $prefix) {
            ($nick, $dummy) = split (/[\!]+/, $prefix, 2);
            if (defined $dummy && $dummy) {
                ($user, $host) = split (/[\@]+/, $dummy, 2);
            }
        }
    }
    elsif ($raw =~ /^(PASS|NICK|USER|SERVER|OPER|QUIT|SQUIT|JOIN|PART|MODE|TOPIC|NAMES|LIST|INVITE|KICK|VERSION|STATS|LINKS|TIME|CONNECT|TRACE|ADMIN|INFO|PRIVMSG|NOTICE|WHO|WHOIS|WHOWAS|KILL|PING|PONG|ERROR|AWAY|REHASH|RESTART|SUMMON|USERS|WALLOPS|USERHOST|ISON)[\s\t]+.*$/i) {
        ($command, $params) = split (/[\s\t]+/, $raw, 2);
    }
    if (! defined $user || ! $user) {
        if (defined $CONN{$client}->{user}) {
            $user = $CONN{$client}->{user};
        }
        else {
            $user = "";
        }
    }
    if (! defined $nick || ! $nick) {
        if (defined $CONN{$client}->{nick}) {
            $nick = $CONN{$client}->{nick};
        }
        else {
            $nick = "";
        }
    }
    if (! defined $host || ! $host) {
        if (defined $CONN{$client}->{host}) {
            $host = $CONN{$client}->{host};
        }
        else {
            $host = "";
        }
    }
#print STDERR "raw: $raw\n";
#print STDERR "user: $user, nick: $nick, host: $host, command: $command, params: $params\n";
    return ($user, $nick, $host, $command, $params);
}


sub PASS {
    my ($self, $user, $nick, $host, $params) = @_;
    my $client = $self->{server}->{client};

    if (! defined $params || ! $params) {
        if ($CONN{$client}->{registered}) {
            $self->send_(":$self->{hostname} 461 $CONN{$client}->{nick} PASS :Not enough parameters");
        }
        else {
            $self->send_(":$self->{hostname} 461 unknown PASS :Not enough parameters");
        }
        return;
    }
    if ($CONN{$client}->{registered}) {
        $self->send_(":$self->{hostname} 462 $CONN{$client}->{nick} :You may not reregister");
        return;
    }
    $CONN{$client}->{pass} = $params;
}


sub NICK {
    my ($self, $user, $nick, $host, $params) = @_;
    my $client = $self->{server}->{client};
    my ($oldnick, $newnick, $hopcount);

    if (! defined $params || ! $params) {
        if ($CONN{$client}->{registered}) {
            $self->send_(":$self->{hostname} 431 $CONN{$client}->{nick} :No nickname given");
        }
        else {
            $self->send_(":$self->{hostname} 431 unknown :No nickname given");
        }
        return;
    }
    $params =~ s/[\s\t]+$//;
    ($newnick, $hopcount) = split (/[\s\t]+/, $params, 2);
    if (defined $NICK{$newnick}) {
        if ($CONN{$client}->{registered}) {
            $self->send_(":$self->{hostname} 433 $CONN{$client}->{nick} :Nickname is already in use");
        }
        else {
            $self->send_(":$self->{hostname} 436 unknown :Nickname collision KILL");
        }
        return;
    }
    $NICK{$newnick} = 1;

    if ($CONN{$client}->{registered}) {
        $oldnick = $CONN{$client}->{nick};
        delete $NICK{$oldnick};
    }
    $CONN{$client}->{nick} = $newnick;
    (defined $hopcount && $hopcount) and $CONN{$client}->{hopcount} = $hopcount;
    if (! $CONN{$client}->{registered}) {
        if ($CONN{$client}->{nick} && $CONN{$client}->{user}) {
            $self->register;
        }
        $self->send_("PING :$self->{hostname}");
    }
    else {
        $self->send_(":$oldnick!$CONN{$client}->{user}\@$CONN{$client}->{host} NICK :$newnick");
        $self->broadcast(":$oldnick!$CONN{$client}->{user}\@$CONN{$client}->{host} NICK :$newnick");
#        $self->broadcast("NOTICE $self->{hostname} #CHAN :$oldnick is now known as $newnick");
    }
}


sub USER {
    my ($self, $user, $nick, $host, $params) = @_;
    my $client = $self->{server}->{client};
    my ($realname, $server);

    if (! defined $params || ! $params) {
        $self->send_(":$self->{hostname} 461 unknown USER :Not enough parameters");
        return;
    }
    ($user, $host, $server, $realname) = split(/[\s\t]+/, $params, 4);
    if (! defined $realname || ! $realname) {
        $self->send_(":$self->{hostname} 461 unknown USER :Not enough parameters");
        return;
    }
    if ($CONN{$client}->{registered}) {
        $self->send_(":$self->{hostname} 462 $CONN{$client}->{nick} :You may not reregister");
        return;
    }
    $realname =~ s/^://;
    $CONN{$client}->{user} = $user;
    $CONN{$client}->{realname} = $realname;
    if ($CONN{$client}->{nick} && $CONN{$client}->{user}) {
        $self->register;
    }
}


sub QUIT {
    my ($self, $user, $nick, $host, $params) = @_;
    my $client = $self->{server}->{client};

    if ($CONN{$client}->{registered}) {
        $self->broadcast("NOTICE $self->{hostname} :User Disconnected: $CONN{$client}->{user}");
    }
    $self->_close;
}


sub PONG {
    my ($self, $user, $nick, $host, $params) = @_;
    my $client = $self->{server}->{client};

    if (! $CONN{$client}->{registered}) {
        $self->send_(":$self->{hostname} 451 unknown * PONG :You have not registered");
        return;
    }
    if (! defined $params || ! $params) {
        $self->send_(":$self->{hostname} 461 $CONN{$client}->{nick} PONG :Not enough parameters");
        return;
    }
    $CONN{$client}->{last_pong} = &INetSim::FakeTime::get_faketime();
}


sub PING {
    my ($self, $user, $nick, $host, $params) = @_;
    my $client = $self->{server}->{client};

    if (! $CONN{$client}->{registered}) {
        $self->send_(":$self->{hostname} 451 unknown * PING :You have not registered");
        return;
    }
    if (! defined $params || ! $params) {
        $self->send_(":$self->{hostname} 461 $CONN{$client}->{nick} PING :Not enough parameters");
        return;
    }
    $params =~ s/^://;
    $self->send_("PONG $params");
}


sub JOIN {
    my ($self, $user, $nick, $host, $params) = @_;
    my $client = $self->{server}->{client};

    if (! $CONN{$client}->{registered}) {
        $self->send_(":$self->{hostname} 451 unknown * JOIN :You have not registered");
        return;
    }
    if (! defined $params || ! $params) {
        $self->send_(":$self->{hostname} 461 $CONN{$client}->{nick} JOIN :Not enough parameters");
        return;
    }
#    $self->broadcast("NOTICE $self->{hostname} :User has joined: $CONN{$client}->{user}");
    $self->broadcast(":$CONN{$client}->{nick}!$CONN{$client}->{user}\@$CONN{$client}->{host} JOIN :$params");
    $self->send_(":$CONN{$client}->{nick}!$CONN{$client}->{user}\@$CONN{$client}->{host} JOIN :$params");
    $params =~ s/^#//;
    $CONN{$client}->{channels} .= "$params,";
}


sub PART {
    my ($self, $user, $nick, $host, $params) = @_;
    my $client = $self->{server}->{client};

    if (! $CONN{$client}->{registered}) {
        $self->send_(":$self->{hostname} 451 unknown * PART :You have not registered");
        return;
    }
    if (! defined $params || ! $params) {
        $self->send_(":$self->{hostname} 461 $CONN{$client}->{nick} PART :Not enough parameters");
        return;
    }
#    $self->broadcast("NOTICE $self->{hostname} #CHAN :User has left: $CONN{$client}->{user}");
    $self->broadcast(":$CONN{$client}->{nick}!$CONN{$client}->{user}\@$CONN{$client}->{host} PART :$params");
    $self->send_(":$CONN{$client}->{nick}!$CONN{$client}->{user}\@$CONN{$client}->{host} PART :$params");
}


sub MODE {
    my ($self, $user, $nick, $host, $params) = @_;
    my $client = $self->{server}->{client};

    if (! $CONN{$client}->{registered}) {
        $self->send_(":$self->{hostname} 451 unknown * MODE :You have not registered");
        return;
    }
    if (! defined $params || ! $params) {
        $self->send_(":$self->{hostname} 461 $CONN{$client}->{nick} MODE :Not enough parameters");
        return;
    }
    $self->send_(":$CONN{$client}->{nick}!$CONN{$client}->{user}\@$CONN{$client}->{host} MODE :$params");
}


sub register {
    my ($self, $sock, $msg) = @_;
    my $client = $self->{server}->{client};

    $CONN{$client}->{registered} = 1;
    # the server sends replies 001 to 004 to a user upon successful registration
    $self->send_(":$self->{hostname} 001 $CONN{$client}->{nick} :Welcome to the Internet Relay Network $CONN{$client}->{nick}");
    $self->send_(":$self->{hostname} 002 $CONN{$client}->{nick} :Your host is $self->{hostname}, running $self->{version}");
    $self->send_(":$self->{hostname} 003 $CONN{$client}->{nick} :This server was created Oct 04 2009 at 02:47:07");
    $self->send_(":$self->{hostname} 004 $CONN{$client}->{nick} :$self->{hostname} $self->{version}");
    # tell the others about the new client
    $self->broadcast("NOTICE $self->{hostname} :User Connected: $CONN{$client}->{user}");
}


sub broadcast {
    my ($self, $msg) = @_;
    my $sclient = $self->{server}->{client};
    my $select = $self->{server}->{select};

    (defined $msg && $msg) or return;
    my @can_write = $select->can_write(0.01);
    foreach my $receiver (@can_write) {
        next if ($receiver == $sclient);
        next if (! $CONN{$receiver}->{registered});
        next if (! $self->{server}->{select}->exists($receiver));
        $self->send_("$msg", $receiver);
    }
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



sub send_ {
    my ($self, $msg, $sock) = @_;
    (defined $sock && $sock) or $sock = $self->{server}->{client};

    (defined $msg) or return;
    $msg =~ s/[\r\n]*//;
    print $sock "$msg\r\n";
    $self->slog_("send: $msg", $sock);
    $CONN{$sock}->{last_send} = &INetSim::FakeTime::get_faketime();
}



sub new {
  my $class = shift || die "Missing class";
  my $args  = @_ == 1 ? shift : {@_};
  my $self  = bless {server => { %$args }}, $class;
  return $self;
}



sub configure_hook {
    my $self = shift;

    $self->{server}->{host}   = &INetSim::Config::getConfigParameter("Default_BindAddress"); # bind to address
    $self->{server}->{port}   = &INetSim::Config::getConfigParameter("IRC_BindPort");
    $self->{server}->{proto}  = 'tcp';                                      # TCP protocol
    $self->{server}->{type}  = SOCK_STREAM;
    $self->{server}->{user}   = &INetSim::Config::getConfigParameter("Default_RunAsUser");       # user to run as
    $self->{server}->{group}  = &INetSim::Config::getConfigParameter("Default_RunAsGroup");    # group to run as

    $self->{servicename} = &INetSim::Config::getConfigParameter("IRC_ServiceName");
    $self->{maxchilds} = &INetSim::Config::getConfigParameter("Default_MaxChilds");
    $self->{timeout} = &INetSim::Config::getConfigParameter("Default_TimeOut");

    $self->{hostname} = &INetSim::Config::getConfigParameter("IRC_FQDN_Hostname");
    $self->{version} = &INetSim::Config::getConfigParameter("IRC_Version");
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
    my ($self, $msg) = @_;

    if (defined $msg) {
        $msg =~ s/[\r\n]*//;
        &INetSim::Log::MainLog("failed! $!", $self->{servicename});
    }
    else {
        &INetSim::Log::MainLog("failed!", $self->{servicename});
    }
    exit 1;
}



sub server_close {
    my $self = shift;

    $self->{server}->{socket}->close();
    exit 0;
}



sub bind {
    my $self = shift;

    # evil untaint
    $self->{server}->{host} =~ /(.*)/;
    $self->{server}->{host} = $1;

    # bind to socket
    $self->{server}->{socket} = new IO::Socket::INET(	Listen		=> 1,
							LocalAddr	=> $self->{server}->{host},
							LocalPort	=> $self->{server}->{port},
							Proto		=> $self->{server}->{proto},
							Type		=> $self->{server}->{type},
							ReuseAddr	=> 1
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
    # standard loop for: _accept->process_request->_close
    $self->loop;
    # just for compatibility with net::server
    $self->pre_server_close_hook;
    # shutdown socket and exit
    $self->server_close;
}


sub _close {
    my $self = shift;
    my $client = $self->{server}->{client};
    my $rhost = $client->peerhost;
    my $rport = $client->peerport;

    &INetSim::Log::SubLog("[$rhost:$rport] disconnect", $self->{servicename}, $$);
    if ($self->{server}->{select}->exists($client)) {
        $self->{server}->{select}->remove($client);
    }
    $client->close;
    delete $CONN{$client};
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
# Version 0.10  (2010-04-19) me
# - use configuration variables for version and hostname
#   instead of static values
#
# Version 0.9   (2010-04-15) th/me
# - removed replacing of non-printable characters before logging
#   as it is already implemented in log module
#
# Version 0.8   (2009-12-18) me
# - do not log 'service stop' twice
#
# Version 0.7   (2009-12-05) me
# - fixed a bug in server reply for nick name change
#
# Version 0.6   (2009-10-14) me
# - added function to split message parts
# - added support for nick name change
#
# Version 0.5   (2009-10-04) me
# - some small fixes
#
# Version 0.4   (2009-10-03) me
# - THIS PROTOCOL IS A DAMNED CRAP ! :-(
# - first very simple implementations for PASS, NICK, USER, JOIN,
#   PART, MODE, PING, PONG and PRIVMSG
#
# Version 0.3   (2009-10-01) me
# - played with IO::Select (try and error)
# - changed initial server greeting
# - added function _accept()
#
# Version 0.2   (2009-09-30) me
# - enhanced in a similar manner like Net::Server
#
# Version 0.1   (2009-09-23) me
# - initial version
#
#############################################################
