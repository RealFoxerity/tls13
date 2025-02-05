CC=gcc
CFLAGS=-O3 -g
LDFLAGS=
OBJS=src/main.o src/server.o src/mime_types.o

all: $(OBJS)
	mkdir -p build
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJS) -o build/http

release: $(OBJS)
	mkdir -p build
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJS) -o build/http
	strip -s build/http

clean:
	rmdir -rf build
	rm $(! find . -name "*.o")

src/main.o: src/server.o
src/server.o: src/mime_types.o