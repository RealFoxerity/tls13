CC=gcc
CFLAGS=-O0 -Og -g -Wall -fPIC
LDFLAGS=-lgmp -L../crypto/build -lbadcrypto
OBJS=$(shell find -name '*.c' | grep -v test | sed 's/\.c$$/.o/g')
#src/crypto/*.o: CFLAGS+=-O3

build/libbadtls.so: ../crypto/build/libbadcrypto.so $(OBJS)
	mkdir -p build
	$(CC) $(CFLAGS) $(OBJS) -shared -o build/libbadtls.so $(LDFLAGS)

.PHONY: ../crypto/build/libbadcrypto.so
../crypto/build/libbadcrypto.so: $(CRYPTO_OBJS)
	$(MAKE) -C ../crypto

tests: build/libbadcrypto.so build/libbadtls.so src/test_tls_funcs.o
	mkdir -p build/tests
	$(CC) $(CFLAGS) src/test_tls_funcs.o -o build/tests/tls $(LDFLAGS) -Lbuild -lbadcrypto -lbadtls

.PHONY: clean
clean:
	rm -rf build
	rm -f $(shell find . -name "*.o")
