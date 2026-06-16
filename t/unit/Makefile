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

.PHONY: all clean

all: $(TARGET)
	./$(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $^ $(OPENSSL_LIBS)

clean:
	rm -f $(TARGET)
