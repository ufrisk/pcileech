import memprocfs
vmm = memprocfs.Vmm()
for process in vmm.process_list():
    for entry in process.maps.pte():
        if '-rwx' in entry['flags']:
            print(str(process.pid) + ': ' + process.name + ': ' + str(entry))