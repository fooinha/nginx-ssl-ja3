#!/usr/bin/perl

# (C) Sergey Kandaurov
# (C) Nginx, Inc.
# (C) Paulo Pacheco

# Tests for SSL/TLS ja3 fingerprint

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Data::Dumper;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

eval { require IO::Socket::SSL; };
plan(skip_all => 'IO::Socket::SSL not installed') if $@;
eval { IO::Socket::SSL::SSL_VERIFY_NONE(); };
plan(skip_all => 'IO::Socket::SSL too old') if $@;

my $t = Test::Nginx->new()->has_daemon('openssl')->plan(1);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080 ssl;
        server_name  localhost;

        ssl_certificate_key localhost.key;
        ssl_certificate localhost.crt;

        location /ja3 {
            return 200 $http_ssl_ja3_hash;
        }
    }
}

EOF

$t->write_file('openssl.conf', <<EOF);
[ req ]
default_bits = 1024
encrypt_key = no
distinguished_name = req_distinguished_name
[ req_distinguished_name ]
EOF

my $d = $t->testdir();

foreach my $name ('localhost') {
    system('openssl req -x509 -new '
        . "-config '$d/openssl.conf' -subj '/CN=$name/' "
        . "-out '$d/$name.crt' -keyout '$d/$name.key' "
        . ">>$d/openssl.out 2>&1") == 0
        or die "Can't create certificate for $name: $!\n";
}

my $ctx = new IO::Socket::SSL::SSL_Context(
    SSL_verify_mode => IO::Socket::SSL::SSL_VERIFY_NONE(),
    SSL_session_cache_size => 100);


$t->run();

###############################################################################

like(get('/ja3', 8080), qr/.*[0-9a-f]{32}/m, 'http_ssl_ja3 var is returned');


###############################################################################

sub get {
    my ($uri, $port) = @_;
    my $s = get_ssl_socket($ctx, port($port)) or return;
    my $r = http_get($uri, socket => $s);

    $s->close();
    return $r;
}

sub get_ssl_socket {
    my ($ctx, $port, %extra) = @_;
    my $s;

    eval {
        local $SIG{ALRM} = sub { die "timeout\n" };
        local $SIG{PIPE} = sub { die "sigpipe\n" };
        alarm(2);
        $s = IO::Socket::SSL->new(
            Proto => 'tcp',
            PeerAddr => '127.0.0.1',
            PeerPort => $port,
            SSL_verify_mode => IO::Socket::SSL::SSL_VERIFY_NONE(),
            SSL_reuse_ctx => $ctx,
            SSL_error_trap => sub { die $_[1] },
            %extra
        );
        alarm(0);
    };
    alarm(0);

    if ($@) {
        log_in("died: $@");
        return undef;
    }

    return $s;
}


###############################################################################
