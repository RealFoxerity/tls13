CC=gcc
CFLAGS=-O0 -Og -g -Wall
LDFLAGS=
OBJS=$(shell find . -name '*.c' | grep -v test | sed 's/\.c$$/.o/g')
CRYPTO_OBJS=$(shell find src/crypto -name '*.c')
#src/crypto/*.o: CFLAGS+=-O3

all: $(OBJS) tests
	mkdir -p build
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJS) -o build/http
	#echo Setting CAP_NET_BIND_SERVICE...; (sudo setcap cap_net_bind_service=ep build/http || echo Failed)

tests: tests_crypto
tests_crypto: $(CRYPTO_OBJS)
	mkdir -p build/tests/crypto
	$(CC) $(CFLAGS) $(LDFLAGS) $(CRYPTO_OBJS) -o build/tests/crypto/crypto_test

release: $(OBJS)
	mkdir -p build
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJS) -o build/http
	strip -s build/http
	#echo Setting CAP_NET_BIND_SERVICE...; (sudo setcap cap_net_bind_service=ep build/http || echo Failed)

clean:
	rm -rf build
	rm -f $(shell find . -name "*.o")

src/main.o: src/server.o src/tls_wrapper.o
src/tls_wrapper.o: src/server.o src/tls_extensions.o
src/server.o: src/mime_types.o
