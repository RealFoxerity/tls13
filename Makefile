CC=gcc
CFLAGS=-O0 -Og -g -Wall
LDFLAGS=-Ltls/build -Lcrypto/build -lbadtls -lbadcrypto
OBJS=$(shell find src -name '*.c' | grep -v test | sed 's/\.c$$/.o/g')

all: tls/build/libbadtls.so crypto/build/libbadcrypto.so $(OBJS)
	mkdir -p build

	cp tls/build/libbadtls.so crypto/build/libbadcrypto.so build

	$(CC) $(CFLAGS) $(OBJS) -o build/http $(LDFLAGS)

	openssl ecparam -name prime256v1 -genkey -outform der -out build/test_secp256r1_priv.der
	openssl req -new -x509 -outform der -key build/test_secp256r1_priv.der -out build/test_secp256r1_pub.der -subj "/C=US/ST=State/L=City/O=Organization/OU=Unit/CN=CommonName"

.PHONY: tls/build/libbadtls.so crypto/build/libbadcrypto.so
tls/build/libbadtls.so:
	$(MAKE) -C tls
crypto/build/libbadcrypto.so:
	$(MAKE) -C crypto

tests:
	$(MAKE) -C tls tests
	$(MAKE) -C crypto tests

release: all
	strip -s build/http
	#echo Setting CAP_NET_BIND_SERVICE...; (sudo setcap cap_net_bind_service=ep build/http || echo Failed) # strip removes caps

.PHONY: clean
clean:
	rm -rf build
	rm -f $(shell find src -name "*.o")
	$(MAKE) -C tls clean
	$(MAKE) -C crypto clean
