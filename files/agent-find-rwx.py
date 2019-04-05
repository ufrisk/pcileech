for pid, procinfo in VmmPy_ProcessListInformation().items():
    try:
        memmap = VmmPy_ProcessGetMemoryMap(pid, True)
        for entry in memmap:
            if '-rwx' in entry['flags']:
                print(str(pid) + ': ' + procinfo['name'] + ': ' + str(entry))
    except:
        pass