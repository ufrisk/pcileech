CC=gcc
CFLAGS  +=-I. -I../includes -D LINUX -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 -pthread
CFLAGS  += -fPIE -fPIC -fstack-protector -D_FORTIFY_SOURCE=2 -O1
CFLAGS  += -Wall -Wno-format-truncation -Wno-enum-compare -Wno-pointer-sign -Wno-multichar -Wno-unused-variable -Wno-unused-value
CFLAGS  += -Wno-pointer-to-int-cast -Wno-int-to-pointer-cast
ifeq ($(shell basename $(CC)),gcc)
    CFLAGS  += -pie
endif
LDFLAGS +=-Wl,-rpath,'$$ORIGIN' -ldl -L. -l:leechcore.so -l:vmm.so -Wl,-z,noexecstack
DEPS = pcileech.h
OBJ  = oscompatibility.o charutil.o device.o pcileech.o executor.o extra.o help.o kmd.o memdump.o mempatch.o statistics.o umd.o util.o vfslist.o vfs.o vmmx.o ob/ob_cachemap.o ob/ob_core.o ob/ob_map.o ob/ob_set.o

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
	rm -f */*.o || true
	rm -f *.so || true
	true

clean:
	rm -f *.o || true
	rm -f */*.o || true
	rm -f *.so || true
