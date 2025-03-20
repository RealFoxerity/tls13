CC=gcc
CFLAGS=-O3 -g
LDFLAGS=
OBJS=src/main.o src/server.o src/mime_types.o src/tls_wrapper.o src/tls_extensions.o

all: $(OBJS)
	mkdir -p build
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJS) -o build/http
	echo Setting CAP_NET_BIND_SERVICE...; (sudo setcap cap_net_bind_service=ep build/http || echo Failed)

release: $(OBJS)
	mkdir -p build
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJS) -o build/http
	strip -s build/http
	echo Setting CAP_NET_BIND_SERVICE...; (sudo setcap cap_net_bind_service=ep build/http || echo Failed)

clean:
	rm -rf build
	rm -f $(! find . -name "*.o")

src/main.o: src/server.o src/tls_wrapper.o
src/tls_wrapper.o: src/server.o src/tls_extensions.o
src/server.o: src/mime_types.o
