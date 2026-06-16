#!/usr/bin/perl

# (C) Paulo Pacheco

# Integration tests for the $stream_ssl_ja3 and $stream_ssl_ja3_hash
# variables exposed by ngx_stream_ssl_ja3_preread_module.
#
# Requires: nginx built with --with-stream --with-stream_ssl_module and
#           the module, IO::Socket::SSL, openssl binary.
# Run with:  prove t/stream_ssl_ja3.t

###############################################################################

use warnings;
use strict;

use Test::More;
use Digest::MD5 qw(md5_hex);

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Nginx::Stream qw(stream);

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

eval { require IO::Socket::SSL; };
plan(skip_all => 'IO::Socket::SSL not installed') if $@;
eval { IO::Socket::SSL::SSL_VERIFY_NONE(); };
plan(skip_all => 'IO::Socket::SSL too old') if $@;

my $t = Test::Nginx->new()
    ->has_daemon('openssl')
    ->has(qw/stream stream_ssl/)
    ->plan(10);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

stream {
    server {
        listen      127.0.0.1:12345 ssl;

        ssl_certificate_key localhost.key;
        ssl_certificate     localhost.crt;

        # Return both variables in one response line
        return "$stream_ssl_ja3|$stream_ssl_ja3_hash\n";
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
# Helper: connect via SSL and read the stream response

sub ssl_stream_get {
    my (%opts) = @_;
    my $s;
    eval {
        local $SIG{ALRM} = sub { die "timeout\n" };
        alarm(4);
        $s = IO::Socket::SSL->new(
            Proto           => 'tcp',
            PeerAddr        => '127.0.0.1',
            PeerPort        => port(12345),
            SSL_verify_mode => IO::Socket::SSL::SSL_VERIFY_NONE(),
            SSL_error_trap  => sub { die $_[1] },
            %opts,
        );
        alarm(0);
    };
    alarm(0);
    return '' unless defined $s;
    local $/ = "\n";
    my $line = <$s>;
    $s->close();
    return defined $line ? $line : '';
}

###############################################################################

# Test 1: response contains the pipe-separated pair
{
    my $r = ssl_stream_get();
    like($r, qr/^[^|]*\|[0-9a-f]{32}/, 'stream: response contains fp|hash pair');
}

# Test 2: hash is a 32-character hex string
{
    my $r = ssl_stream_get();
    $r =~ /\|([0-9a-f]+)/;
    is(length($1 // ''), 32, 'stream_ssl_ja3_hash: is 32 hex chars');
}

# Test 3: raw fingerprint has the 5-field comma-separated format
{
    my $r = ssl_stream_get();
    my ($fp) = $r =~ /^([^|]+)\|/;
    like($fp // '', qr/^\d+,[0-9-]*,[0-9-]*,[0-9-]*,[0-9-]*$/,
         'stream_ssl_ja3: format matches spec');
}

# Test 4: version field is a known TLS version
{
    my $r = ssl_stream_get();
    my ($fp) = $r =~ /^([^|]+)\|/;
    like($fp // '', qr/^(769|770|771|772),/,
         'stream_ssl_ja3: version field is a known TLS version');
}

# Test 5: hash equals md5(fingerprint)
{
    my $r = ssl_stream_get();
    chomp $r;
    my ($fp, $hash) = split /\|/, $r;
    if (defined $fp && defined $hash && $fp =~ /\S/) {
        is(md5_hex($fp), $hash, 'stream_ssl_ja3_hash: equals md5(stream_ssl_ja3)');
    } else {
        fail('stream: could not split fp|hash');
    }
}

# Test 6: fingerprint is consistent across two identical connections
{
    my ($r1) = (ssl_stream_get() =~ /\|([0-9a-f]+)/);
    my ($r2) = (ssl_stream_get() =~ /\|([0-9a-f]+)/);
    is($r1 // 'a', $r2 // 'b', 'stream: same settings produce same hash');
}

# Test 7: TLS 1.2 version field is 771
{
    my $r  = ssl_stream_get(SSL_cipher_list => 'AES128-SHA', SSL_version => 'TLSv1_2');
    my ($fp) = $r =~ /^([^|]+)\|/;
    like($fp // '', qr/^771,/, 'stream_ssl_ja3: TLS 1.2 version is 771');
}

# Test 8: different cipher restrictions produce different fingerprints
{
    my ($h1) = (ssl_stream_get(SSL_cipher_list => 'AES128-SHA',   SSL_version => 'TLSv1_2') =~ /\|([0-9a-f]+)/);
    my ($h2) = (ssl_stream_get(SSL_cipher_list => 'AES256-SHA256', SSL_version => 'TLSv1_2') =~ /\|([0-9a-f]+)/);
    like($h1 // '', qr/^[0-9a-f]{32}$/, 'stream: AES128-SHA hash is valid');
    like($h2 // '', qr/^[0-9a-f]{32}$/, 'stream: AES256-SHA256 hash is valid');
    isnt($h1 // 'x', $h2 // 'y', 'stream: different cipher list gives different hash');
}

###############################################################################

$t->stop();
