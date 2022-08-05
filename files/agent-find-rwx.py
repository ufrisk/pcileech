# Example file to demonstrate remote python functionality with the LeechAgent.
#
# Example:
# pcileech.exe -device <device> -remote rpc://<spn or insecure>:host agent-execpy -in agent-find-rwx.py
#
# The python script will be executed in a child process to the LeechAgent in
# the user-context of the LeechAgent. If the agent is running as a service this
# is most likely SYSTEM. It's also possible to use this functionality to run
# Python scripts on the remote host without using the memory analysis functionality.
#
# Please check out agent installation instructions at:
# https://github.com/ufrisk/LeechCore/wiki/LeechAgent
# https://github.com/ufrisk/LeechCore/wiki/LeechAgent_Install
#


#
# Example to load LeechCore for Python connecting to the memory acqusition device
# specified in the PCILeech -device parameter. Please uncomment to activate.
# Guide at: https://github.com/ufrisk/LeechCore/wiki/LeechCore_API_Python
#
'''
import leechcorepyc
lc = leechcorepyc.LeechCore('existing')
print(lc)
'''


#
# Example to load MemProcFS for Python connecting to the memory acqusition device
# specified in the PCILeech -device parameter.
# For information about MemProcFS Python API please check out the wiki for API
# usage examples and a youtube demo.
# https://github.com/ufrisk/MemProcFS/wiki/API_Python
# 
#
import memprocfs
vmm = memprocfs.Vmm(['-device', 'existingremote'])
for process in vmm.process_list():
    for entry in process.maps.pte():
        if '-rwx' in entry['flags']:
            print(str(process.pid) + ': ' + process.name + ': ' + str(entry))
