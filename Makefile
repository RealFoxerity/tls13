CC=gcc
CFLAGS=-O0 -Og -g -Wall -fPIC
LDFLAGS=-lgmp
TLS_WRAPPER_OBJS=$(shell find src/ -maxdepth 1 -name '*.c' | grep -v test | sed 's/\.c$$/.o/g')
CRYPTO_OBJS=$(shell find src/crypto -name '*.c' | grep -v test | sed 's/\.c$$/.o/g')
SERVER_OBJS=$(shell find src/http -name '*.c' | grep -v test | sed 's/\.c$$/.o/g')
#src/crypto/*.o: CFLAGS+=-O3

all: $(SERVER_OBJS) build/libbadtls.so build/libbadcrypto.so
	mkdir -p build
	$(CC) $(CFLAGS) $(LDFLAGS) $(SERVER_OBJS) -Lbuild -lbadtls -lbadcrypto -o build/http
	#echo Setting CAP_NET_BIND_SERVICE...; (sudo setcap cap_net_bind_service=ep build/http || echo Failed) # to be able to run the server without root, commented out because it doesn't work on NFS (my rootfs)

build/libbadtls.so: $(TLS_WRAPPER_OBJS)
	mkdir -p build
	$(CC) $(CFLAGS) $(LDFLAGS) $(TLS_WRAPPER_OBJS) -shared -o build/libbadtls.so

build/libbadcrypto.so: $(CRYPTO_OBJS)
	mkdir -p build
	$(CC) $(CFLAGS) $(LDFLAGS) $(CRYPTO_OBJS) -shared -o build/libbadcrypto.so

tests: tests_crypto
tests_crypto: build/libbadcrypto.so src/crypto/test_crypto_suite.o
	mkdir -p build/tests/crypto
	$(CC) $(CFLAGS) $(LDFLAGS) src/crypto/test_crypto_suite.o -Lbuild -lbadcrypto -o build/tests/crypto/crypto_test

release: all
	strip -s build/http
	#echo Setting CAP_NET_BIND_SERVICE...; (sudo setcap cap_net_bind_service=ep build/http || echo Failed) # strip removes caps

clean:
	rm -rf build
	rm -f $(shell find . -name "*.o")
