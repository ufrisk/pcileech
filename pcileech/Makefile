CC=gcc
CFLAGS  +=-I. -I../includes -D LINUX -L. -l:leechcore.so -l:vmm.so -pthread
#CFLAGS  += -g -O0
CFLAGS  += -fPIE -pie -fstack-protector -D_FORTIFY_SOURCE=2 -O1 -Wl,-z,noexecstack
CFLAGS  += -Wall -Wno-format-truncation -Wno-enum-compare -Wno-pointer-sign -Wno-multichar -Wno-unused-variable -Wno-unused-value
CFLAGS  += -Wno-pointer-to-int-cast -Wno-int-to-pointer-cast
LDFLAGS +=-Wl,-rpath,'$$ORIGIN' -ldl
DEPS = pcileech.h
OBJ = oscompatibility.o device.o pcileech.o executor.o extra.o help.o kmd.o memdump.o mempatch.o statistics.o umd.o util.o vfs.o vmmx.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

pcileech: $(OBJ)
	cp ../files/vmm.so . || cp ../../MemProcFS*/files/vmm.so . || true
	cp ../files/leechcore.so . || cp ../../LeechCore*/files/leechcore.so . || true
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)
	mv pcileech ../files/ |true
	mv vmm.so ../files/ |true
	mv leechcore.so ../files/ |true
	rm -f *.o || true
	rm -f *.so || true
	true

clean:
	rm -f *.o || true
	rm -f *.so || true
