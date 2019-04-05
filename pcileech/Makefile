CC=gcc
CFLAGS=-I. -D LINUX -L. -l:leechcore.so -pthread `pkg-config libusb-1.0 --libs --cflags`
LDFLAGS=-Wl,-rpath,'$$ORIGIN'
DEPS = pcileech.h
OBJ = pcileech oscompatibility.o pcileech.o device.o executor.o extra.o help.o kmd.o memdump.o mempatch.o statistics.o umd.o util.o vfs.o vmmprx.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

pcileech: $(OBJ)
	cp ../files/leechcore.so . |true
	cp ../../LeechCore-dev/files/leechcore.so . |true
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)
	rm *.o
	mv pcileech ../files/ |true
	mv leechcore.so ../files/ |true

clean:
	rm *.o
