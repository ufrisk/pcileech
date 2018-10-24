**pcileech WebRadar** Undetected Counter-Strike: Global Offensive Hardware Cheat for VAC, ESEA, FaceIt

pcileech WebRadar is a browser based radar cheat for CS:GO that can be run on a different PC, connected to a PCIe card providing direct memory access to the target computer. For more information about this technology, please visit the repo of the original (and very great) [pcileech project by Ulf Frisk](https://github.com/ufrisk/pcileech)

**Features**
 - Overview Radar showing non-dormant players
 - Health indicator
 - View direction indicator
 - Name tags


**Getting started**

You need to get compatible hardware and flash it with the pcileech software first. Please refer to [this page](https://github.com/ufrisk/pcileech/blob/master/readme.md#hardware).
Afterwards you have to complete the following installation steps:

 - Clone the project and its submodule(s)
 - Compile pcileech
 - Get [FTD3XX.dll](http://www.ftdichip.com/Drivers/D3XX/FTD3XXLibrary_v1.2.0.6.zip) and copy it to *pcileech_files\*
 - Navigate to *Steam\steamapps\common\Counter-Strike Global Offensive\csgo\resource\overviews\*
 - Copy all .txt files to *pcileech_files\static\*
 - Convert all .dds files to png (for example using [this tool](http://www.ddsconverter.com/)) and also copy them to *pcileech_files\static\*
 - Open a command prompt and execute *pcileech.exe webradar*
 - Open a webbrowser on any device in the same network and navigate to http://ip-of-attacker:8008/
 - If you can't connect, make sure to run pcileech as Administrator

 
**Security considerations**

Current known detection vectors for anti cheats and fixes are:

 - Vendor-/DeviceId of the FPGA Device -> build the firmware yourself and randomize the Device ID (instructions for the SP-605 can be found [here](https://github.com/ufrisk/pcileech-fpga/blob/master/sp605_ft601/build.md))
 - The webserver for the webradar -> setup Windows Firewall on the computer that runs pcileech to reject connections from the target PC.

 
**Issues**

 - Currently the setup is not always stable, you might need to restart the game and/or pcileech several times for it to work
 - ~~Memory offsets for CS:GO need to be adjusted in the source code (webradar.c) after every game update~~ **Update: pcileech-webradar now includes offsets dumped with Hazedumper as a submodule**
 - The HTTP Server code is written very hasty and dirty because I wanted to implement websockets first but gave up
 - If you notice any other issues, please report them :)

**Screenshot**
![example screenshot](https://u.sky.fail/e53209def0c03871068.png)
