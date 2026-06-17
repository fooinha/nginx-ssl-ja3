#!/usr/bin/perl

# (C) Paulo Pacheco

# Integration tests for the $stream_ssl_ja4 variable exposed by
# ngx_stream_ssl_ja4_preread_module.
#
# JA4 format: t{ver}{sni}{nc:02d}{ne:02d}{alpn}_{cipher_hash}_{ext_hash}
#   total length: 36 chars
#
# Requires: nginx built with --with-stream --with-stream_ssl_module and
#           the module, IO::Socket::SSL, openssl binary.
# Run with:  prove t/stream_ssl_ja4.t
#            TEST_NGINX_BINARY=/path/to/nginx prove t/stream_ssl_ja4.t

###############################################################################

use warnings;
use strict;

use Test::More;

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
        listen      127.0.0.1:%%PORT_12345%% ssl;

        ssl_certificate_key localhost.key;
        ssl_certificate     localhost.crt;

        return "$stream_ssl_ja4\n";
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

sub ssl_stream_ja4 {
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
    chomp($line //= '');
    return $line;
}

###############################################################################

# Test 1: fingerprint is exactly 36 characters
{
    my $fp = ssl_stream_ja4();
    is(length($fp), 36, 'stream_ssl_ja4: fingerprint is 36 chars');
}

# Test 2: format t{ver}{sni}{nc:02d}{ne:02d}{alpn}_{12hex}_{12hex}
{
    my $fp = ssl_stream_ja4();
    like($fp, qr/^t[0-9s]{2}[di]\d{2}\d{2}[a-z0-9]{2}_[0-9a-f]{12}_[0-9a-f]{12}$/,
         'stream_ssl_ja4: fingerprint matches format');
}

# Test 3: TLS 1.3 version encoded as '13'
{
    my $fp = ssl_stream_ja4();
    like($fp, qr/^t13/, 'stream_ssl_ja4: TLS 1.3 encoded as 13');
}

# Test 4: SNI present
{
    my $fp = ssl_stream_ja4(SSL_hostname => 'localhost');
    like($fp, qr/^t..d/, 'stream_ssl_ja4: SNI present → d');
}

# Test 5: SNI absent
{
    my $fp = ssl_stream_ja4(SSL_hostname => '');
    like($fp, qr/^t..i/, 'stream_ssl_ja4: SNI absent → i');
}

# Test 6: TLS 1.2 version encoded as '12'
{
    my $fp = ssl_stream_ja4(SSL_cipher_list => 'AES128-SHA', SSL_version => 'TLSv1_2');
    like($fp, qr/^t12/, 'stream_ssl_ja4: TLS 1.2 encoded as 12');
}

# Test 7: cipher count is non-zero
{
    my $fp = ssl_stream_ja4();
    my ($nc) = $fp =~ /^t[0-9s]{2}[di](\d{2})/;
    ok(defined $nc && $nc > 0, 'stream_ssl_ja4: cipher count > 0');
}

# Test 8: extension count is non-zero
{
    my $fp = ssl_stream_ja4();
    my ($ne) = $fp =~ /^t[0-9s]{2}[di]\d{2}(\d{2})/;
    ok(defined $ne && $ne > 0, 'stream_ssl_ja4: extension count > 0');
}

# Test 9: fingerprint is consistent across identical connections
{
    my $fp1 = ssl_stream_ja4();
    my $fp2 = ssl_stream_ja4();
    is($fp1, $fp2, 'stream_ssl_ja4: same settings produce same fingerprint');
}

# Test 10: TLS 1.2 and TLS 1.3 produce different fingerprints
{
    my $fp13 = ssl_stream_ja4();
    my $fp12 = ssl_stream_ja4(SSL_cipher_list => 'AES128-SHA', SSL_version => 'TLSv1_2');
    isnt($fp13, $fp12, 'stream_ssl_ja4: TLS 1.3 and TLS 1.2 produce different fingerprints');
}

###############################################################################

$t->stop();
