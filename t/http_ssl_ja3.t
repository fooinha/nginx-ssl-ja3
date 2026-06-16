#!/usr/bin/perl

# (C) Sergey Kandaurov
# (C) Nginx, Inc.
# (C) Paulo Pacheco

# Integration tests for the $http_ssl_ja3 and $http_ssl_ja3_hash variables.
#
# Requires: nginx built with the module, IO::Socket::SSL, openssl binary.
# Run with:  prove t/http_ssl_ja3.t
#            TEST_NGINX_BINARY=/path/to/nginx prove t/http_ssl_ja3.t

###############################################################################

use warnings;
use strict;

use Test::More;
use Digest::MD5 qw(md5_hex);

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

eval { require IO::Socket::SSL; };
plan(skip_all => 'IO::Socket::SSL not installed') if $@;
eval { IO::Socket::SSL::SSL_VERIFY_NONE(); };
plan(skip_all => 'IO::Socket::SSL too old') if $@;

my $t = Test::Nginx->new()->has_daemon('openssl')->plan(14);

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
        ssl_certificate     localhost.crt;

        # Return both variables so tests can check either
        location /ja3 {
            return 200 $http_ssl_ja3;
        }
        location /ja3hash {
            return 200 $http_ssl_ja3_hash;
        }
        location /both {
            return 200 "$http_ssl_ja3|$http_ssl_ja3_hash";
        }
    }
}

EOF

$t->write_file('openssl.conf', <<EOF);
[ req ]
default_bits = 2048
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

$t->run();

###############################################################################
# Helper: make an SSL socket with given options
sub ssl_socket {
    my (%opts) = @_;
    my $s;
    eval {
        local $SIG{ALRM} = sub { die "timeout\n" };
        alarm(4);
        $s = IO::Socket::SSL->new(
            Proto            => 'tcp',
            PeerAddr         => '127.0.0.1',
            PeerPort         => port(8080),
            SSL_verify_mode  => IO::Socket::SSL::SSL_VERIFY_NONE(),
            SSL_error_trap   => sub { die $_[1] },
            %opts,
        );
        alarm(0);
    };
    alarm(0);
    return $s;
}

sub http_get_via_ssl {
    my ($uri, %opts) = @_;
    my $s = ssl_socket(%opts) or return '';
    my $r = http_get($uri, socket => $s);
    $s->close();
    return $r;
}

sub body {
    my ($response) = @_;
    return '' unless defined $response;
    $response =~ s/.*?\r\n\r\n//s;
    return $response;
}

###############################################################################
# Test 1: hash variable is returned and is a 32-character hex string
{
    my $r = http_get_via_ssl('/ja3hash');
    like(body($r), qr/^[0-9a-f]{32}$/, 'ja3hash: 32-char hex string');
}

# Test 2: raw fingerprint variable is returned in the expected format
# Format: version,ciphers,extensions,curves,point_formats  (4 commas total)
{
    my $r = http_get_via_ssl('/ja3');
    like(body($r), qr/^\d+,[0-9-]*,[0-9-]*,[0-9-]*,[0-9-]*$/,
         'ja3: raw fingerprint format matches spec');
}

# Test 3: raw fingerprint starts with a valid TLS version number
#         TLS 1.0=769, TLS 1.1=770, TLS 1.2=771, TLS 1.3=772
{
    my $r = http_get_via_ssl('/ja3');
    like(body($r), qr/^(769|770|771|772),/, 'ja3: version field is a known TLS version');
}

# Test 4: hash is the MD5 of the raw fingerprint string
{
    my $rb   = body(http_get_via_ssl('/both'));
    my ($fp, $hash) = split /\|/, $rb;
    if (defined $fp && defined $hash && $fp =~ /\S/) {
        is(md5_hex($fp), $hash, 'ja3hash: equals md5(ja3 fingerprint)');
    } else {
        fail('ja3hash: could not retrieve both variables');
    }
}

# Test 5: fingerprint is consistent across two connections with the same settings
{
    my $r1 = body(http_get_via_ssl('/ja3hash'));
    my $r2 = body(http_get_via_ssl('/ja3hash'));
    is($r1, $r2, 'ja3hash: same settings produce same hash');
}

# Test 6: restricting to a single cipher changes the fingerprint
{
    my $default = body(http_get_via_ssl('/ja3hash'));
    my $restricted = body(http_get_via_ssl('/ja3hash',
        SSL_cipher_list => 'AES128-SHA',
        SSL_version     => 'TLSv1_2',
    ));
    # Both must be valid hashes
    like($default,    qr/^[0-9a-f]{32}$/, 'ja3hash: default cipher: valid hash');
    like($restricted, qr/^[0-9a-f]{32}$/, 'ja3hash: restricted cipher: valid hash');
    # They should differ (different cipher list → different fingerprint)
    isnt($default, $restricted, 'ja3hash: different cipher list gives different hash');
}

# Test 7: TLS 1.2 fingerprint contains "771" as the version field
{
    my $fp = body(http_get_via_ssl('/ja3',
        SSL_cipher_list => 'AES128-SHA',
        SSL_version     => 'TLSv1_2',
    ));
    like($fp, qr/^771,/, 'ja3: TLS 1.2 version field is 771');
}

# Test 8: fingerprint ciphers field is non-empty for a forced single cipher
{
    my $fp = body(http_get_via_ssl('/ja3',
        SSL_cipher_list => 'AES128-SHA',
        SSL_version     => 'TLSv1_2',
    ));
    # Format: 771,<ciphers>,...  — ciphers field must not be empty
    like($fp, qr/^771,[0-9]+/, 'ja3: ciphers field is non-empty for known cipher');
}

# Test 9: two requests with the same cipher restriction produce the same hash
{
    my %opts = (SSL_cipher_list => 'AES128-SHA', SSL_version => 'TLSv1_2');
    my $h1 = body(http_get_via_ssl('/ja3hash', %opts));
    my $h2 = body(http_get_via_ssl('/ja3hash', %opts));
    is($h1, $h2, 'ja3hash: repeatable under identical TLS 1.2 / AES128-SHA settings');
}

###############################################################################

$t->stop();
