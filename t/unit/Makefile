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

SRCS    = test_ngx_ssl_ja3_fp.c $(SRC_DIR)/ngx_ssl_ja3.c
TARGET  = test_ngx_ssl_ja3_fp

.PHONY: all clean coverage

all: $(TARGET)
	./$(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $^ $(OPENSSL_LIBS)

coverage: clean
	$(CC) $(CFLAGS) --coverage -O0 -fprofile-abs-path \
	    -o $(TARGET) $(SRCS) $(OPENSSL_LIBS)
	./$(TARGET)
	lcov --capture --directory . \
	     --output-file coverage.info --quiet 2>/dev/null
	lcov --extract coverage.info '*/ngx_ssl_ja3.c' \
	     --output-file coverage.info --quiet 2>/dev/null
	lcov --list coverage.info

clean:
	rm -f $(TARGET) *.gcno *.gcda *.gcov coverage.info
