CC=gcc
CFLAGS=-O0 -Og -g -Wall -fPIC
LDFLAGS=-lgmp
OBJS=$(shell find . -name '*.c' | grep -v test | sed 's/\.c$$/.o/g')

build/libbadcrypto.so: $(OBJS)
	mkdir -p build
	$(CC) $(CFLAGS) $(OBJS) -shared -o build/libbadcrypto.so $(LDFLAGS)

tests: build/libbadcrypto.so crypto/test_crypto_suite.o
	mkdir -p build/tests
	$(CC) $(CFLAGS) crypto/test_crypto_suite.o -o build/tests/crypto $(LDFLAGS) -Lbuild -lbadcrypto

.PHONY: clean
clean:
	rm -fr build
	rm -f $(shell find -name "*.o")
