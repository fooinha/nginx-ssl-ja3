# nginx-ssl-ja3  [![Build Status](https://travis-ci.org/fooinha/nginx-ssl-ja3.svg?branch=master)](https://travis-ci.org/fooinha/nginx-ssl-ja3)

nginx module for SSL/TLS ja3 fingerprint.

## Description

This module adds to nginx the ability of new nginx variables for the TLS/SSL ja3 fingerprint.

For details about the ja3 fingerprint algorithm, check initial [project](https://github.com/salesforce/ja3).

## Configuration

### Directives

No directives yet.

### Variables

#### $http_ssl_ja3_hash

The ja3 fingerprint MD5 hash for a SSL connection for a HTTP server.

Example:

```
http {
    server {
        listen                 127.0.0.1:443 ssl;
        ssl_certificate        cert.pem;
        ssl_certificate_key    rsa.key;
        error_log              /dev/stderr debug;
        return                 200 "$time_iso8601-$http_ssl_ja3_hash\n";
    }
}
```

#### $stream_ssl_ja3_hash

The ja3 fingerprint MD5 hash for a SSL connection for a stream server.

Example:

```
stream {
    server {
        listen                 127.0.0.1:12345 ssl;
        ssl_certificate        cert.pem;
        ssl_certificate_key    rsa.key;
        error_log              /dev/stderr debug;
        return                 "$time_iso8601-$stream_ssl_ja3_hash\n";
    }
}
```

## Build

### Dependencies

* [OpenSSL](https://github.com/openssl) - 1.1.1 (dev master version)

The master version OpenSSL is required because this module fetches the
extensions types declared at SSL/TLS Client Hello by using the new early
callback [SSL_CTX_set_client_hello_cb](https://www.openssl.org/docs/manmaster/man3/SSL_CTX_set_client_hello_cb.html).

I was unable to find a way to get these values with the current versions of
nginx and OpenSSL.

So, in order to, have the client extensions available for the fingerprint,
we also need to apply a patch to the nginx code.

If you use, for development, the [docker](#docker) supplied in this repo,
the patch is already applied. Check the Dockerfile of the dev image.

### Patches

 - [save Client Hello extensions at nginx's SSL connection](docker/debian-nginx-ssl-ja3/nginx.ssl.extensions.patch)


### Compilation and installation

Build as a common nginx module.

```bash
$ ./configure --add-module=/build/ngx_ssl_ja3 --with-http_ssl_module --with-stream_ssl_module --with-debug --with-stream
$ make && make install

```
## Tests

Make sure that the lib directory for nginx-tests is available in the 't' directory.


```
$ TEST_NGINX_BINARY=/usr/local/nginx/sbin/nginx prove -v
```

## Docker

Docker images and a docker compose file is available at the ./docker directory.

```
$ docker-compose up --build -d

Creating nginx-ssl-ja3

```

## Fair Warning

**THIS IS NOT PRODUCTION** ready.

So there's no guarantee of success. It most probably blow up when running in real life scenarios.

