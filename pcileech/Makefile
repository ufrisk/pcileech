CC=gcc
CFLAGS=-I. -I../includes -D LINUX -L. -l:leechcore.so -pthread
LDFLAGS=-Wl,-rpath,'$$ORIGIN' -ldl
DEPS = pcileech.h
OBJ = oscompatibility.o device.o pcileech.o executor.o extra.o help.o kmd.o memdump.o mempatch.o statistics.o umd.o util.o vfs.o vmmx.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

pcileech: $(OBJ)
	cp ../files/leechcore.so . |true
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)
	rm *.o
	mv pcileech ../files/ |true
	mv leechcore.so ../files/ |true

clean:
	rm -f *.o
	rm -f *.so
