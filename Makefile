all: unpacker
run: unpacker
	./unpacker imgs/tiny.png

LDFLAGS=    -lm -lz
CFLAGS=     -g

unpacker: png_unpacker.o
	$(CC) $(CLFAGS) -o $@ $^ $(LDFLAGS) 

gdb: unpacker
	gdb $^ -ex="b main" -ex="layout src" -ex="run img.png" -ex="set disassembly-flavor intel"

clean:
	rm -f unpacker *.o
