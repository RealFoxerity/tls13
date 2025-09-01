CC=gcc
CFLAGS=-Og -g
LDFLAGS=
OBJS=$(shell find . -name '*.c' | grep -v test | sed 's/\.c$$/.o/g')

all: $(OBJS) tests
	mkdir -p build
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJS) -o build/http
	echo Setting CAP_NET_BIND_SERVICE...; (sudo setcap cap_net_bind_service=ep build/http || echo Failed)

tests: tests_crypto
tests_crypto: src/crypto/sha3.o src/crypto/test_crypto_suite.o
	mkdir -p build/tests/crypto
	$(CC) $(CFLAGS) $(LDFLAGS) src/crypto/sha3.o src/crypto/test_crypto_suite.o -o build/tests/crypto/crypto_test

release: $(OBJS)
	mkdir -p build
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJS) -o build/http
	strip -s build/http
	echo Setting CAP_NET_BIND_SERVICE...; (sudo setcap cap_net_bind_service=ep build/http || echo Failed)

clean:
	rm -rf build
	rm -f $(shell find . -name "*.o")

src/main.o: src/server.o src/tls_wrapper.o
src/tls_wrapper.o: src/server.o src/tls_extensions.o
src/server.o: src/mime_types.o
