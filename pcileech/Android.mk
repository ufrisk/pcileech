# Build file for Android version of PCILeech
#
# To build follow these steps:
# 1) Ensure Andoid NDK is installed and on path.
# 2) Get a copy of libusb from github.com/libusb/libusb/
# 2) Set PATH_TO_LIBUSB_SRC environment variable to libusb source.
# 3) Build: ndk-build APP_BUILD_SCRIPT=./Android.mk NDK_PROJECT_PATH=.
#
include $(PATH_TO_LIBUSB_SRC)/android/jni/libusb.mk
include $(CLEAR_VARS)
LOCAL_PATH := .

LOCAL_CFLAGS := -D ANDROID 
LOCAL_LDLIBS := -L$(LOCAL_PATH)/lib -llog -g

LOCAL_C_INCLUDES := bionic
LOCAL_SRC_FILES:= pcileech.c oscompatibility.c device.c device3380.c devicefile.c devicefpga.c device605_tcp.c executor.c extra.c help.c kmd.c memdump.c mempatch.c statistics.c tlp.c util.c vfs.c vmm.c vmmproc.c

LOCAL_MODULE := pcileech
LOCAL_SHARED_LIBRARIES += libusb1.0

include $(BUILD_EXECUTABLE)
