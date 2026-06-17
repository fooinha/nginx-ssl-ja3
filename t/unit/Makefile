CC      ?= cc
SRC_DIR  = ../../src

OPENSSL_CFLAGS := $(shell pkg-config --cflags openssl 2>/dev/null || \
                  echo -I/opt/homebrew/opt/openssl@3/include -I/usr/local/include)
OPENSSL_LIBS   := $(shell pkg-config --libs   openssl 2>/dev/null || \
                  echo -L/opt/homebrew/opt/openssl@3/lib -lssl -lcrypto)

CFLAGS  = -std=c99 -Wall -Wextra -Wpedantic \
          -I./stubs \
          -I$(SRC_DIR) \
          $(OPENSSL_CFLAGS)

TARGETS = test_ngx_ssl_ja3_fp test_ngx_ssl_ja4_fp

.PHONY: all clean coverage

all: $(TARGETS)
	./test_ngx_ssl_ja3_fp
	./test_ngx_ssl_ja4_fp

test_ngx_ssl_ja3_fp: test_ngx_ssl_ja3_fp.c
	$(CC) $(CFLAGS) -o $@ $< $(OPENSSL_LIBS)

test_ngx_ssl_ja4_fp: test_ngx_ssl_ja4_fp.c
	$(CC) $(CFLAGS) -o $@ $< $(OPENSSL_LIBS)

coverage: clean
	$(CC) $(CFLAGS) --coverage -O0 -fprofile-abs-path \
	    -o test_ngx_ssl_ja3_fp test_ngx_ssl_ja3_fp.c $(OPENSSL_LIBS)
	$(CC) $(CFLAGS) --coverage -O0 -fprofile-abs-path \
	    -o test_ngx_ssl_ja4_fp test_ngx_ssl_ja4_fp.c $(OPENSSL_LIBS)
	./test_ngx_ssl_ja3_fp
	./test_ngx_ssl_ja4_fp
	lcov --capture --directory . \
	     --output-file coverage.info --quiet 2>/dev/null
	lcov --extract coverage.info '*/ngx_ssl_ja3.c' '*/ngx_ssl_ja4.c' '*/ngx_ssl_ja4s.c' \
	     --output-file coverage.info --quiet 2>/dev/null
	lcov --list coverage.info

clean:
	rm -f $(TARGETS) *.gcno *.gcda *.gcov coverage.info
