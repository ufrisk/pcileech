Android Information:
====================
This page contains specific information about PCILeech with regards to installing and building for Android. For general information about PCIleech please check the [readme](README.md).

PCILeech is able to run on Android devices - such as phones and tablets. The device must be rooted and PCIleech must be run as root. The Android device must have a USB port which the PCILeech hardware can be connected to. Most devices, such as phones, supports OTG which will allow connecting PCILeech with an OTG adapter.

<img src="https://gist.githubusercontent.com/ufrisk/c5ba7b360335a13bbac2515e5e7bb9d7/raw/314e527e13e78edd44cc6db2b7c05cfa4a1ce322/_gh_android.jpg" height="250"/>

PCILeech on the Nexus 5x dumping memory from a Lenovo T430.

Installing
==========
Please ensure you do have the most recent version of PCILeech by downloading it from: https://github.com/ufrisk/pcileech

Either build your own binaries, or download the pre-built [PCILeech v2.1 Android binaries](https://gist.github.com/ufrisk/d783ef49813a269704f3bce1c022cefb/raw/1392da4748c357dc0436f94f91f2128cfa5a7374/pcileech_android_v21.zip). SHA-256: `f48c9269e3cdf6cbf884970b2665d111a0d04bdf3008fdea62eddf793c9211cf`

Run the commands below as root on Android device to install PCILeech:
* Remount system file system as read/write: `mount -o remount,rw /system`
* Copy `<arch>/libusb1.0.so` from the downloaded or built Android binaries to `/system/lib/` or `/system/lib64/` (depending on device cpu architecture).
* Remount system file system as read-only: `mount -o remount,ro /system`
* Create PCILeech directory: `mkdir /data/pcileech/`
* Copy `<arch>/pcileech` from the downloaded or built Android binaries to `/data/pcileech/`.
* Copy from `pcileech_files/`: *.sig, *.ksh, *.kmd *.bin files to `/data/pcileech/`

Finished! PCILeech should now be able to run on the phone!

Tested on Nexus 5x with Apple USB-C to USB OTG adapter.

Building
========
Building PCILeech for Android has been tested on a Linux x64-system (Kali and Ubuntu amd64 versions). Please follow the instructions below for building PCILeech for Android:
* Download and install the Android NDK.
* Ensure ndk-build is on the current path.
* Get the latest libusb source from: `https://github.com/libusb/libusb`
* Get the latest pcileech source from: `https://github.com/ufrisk/pcileech`
* Set environment variable PATH_TO_LIBUSB_SRC: `export PATH_TO_LIBUSB_SRC=</path/to/libusb/source>`
* Move into: `<path/to/pcileech/soruce>/pcileech/`
* Execute: `ndk-build APP_BUILD_SCRIPT=./Android.mk NDK_PROJECT_PATH=.`
* Finished! PCIleech and Libusb Android binaries should now be found in the libs folder.
