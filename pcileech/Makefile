CC=gcc
CFLAGS=-I. -D LINUX -pthread `pkg-config libusb-1.0 --libs --cflags`
DEPS = pcileech.h
OBJ = pcileech oscompatibility.o pcileech.o device.o device3380.o devicefile.o devicefpga.o device605_tcp.o devicetmd.o executor.o extra.o help.o kmd.o memdump.o mempatch.o statistics.o tlp.o util.o vfs.o vmm.o vmmproc.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

pcileech: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) 

clean:
	rm *.o
