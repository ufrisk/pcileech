// pcilech_kmd.c : Linux kernel module for PCILeech.
// Use this module on systems you already have root access on and that PCILeech
// cannot insert a kernel module directly by normal means (4.8 kernel).
//
// (c) Ulf Frisk, 2016
// Author: Ulf Frisk, pcileech@frizk.net
//
// Compiling:
//  - To compile this kernel module go to the  folder  containing this file and
//    type make. GCC and kernel headers are required.    If successful read the
//    usage section below.
// Usage:
//  - run 'insmod pcileech_kmd.ko'. If the module is successfully inserted then
//    the kmd should be successfully loaded into the kernel. Check the physical
//    memory address with the 'dmesg' command.  At the bottom of the dmesg text
//    there should be a text like 'pcileech: success - kmd loaded at address:'.
//    Use the address as an argument to the kmd parameter in pcileech. 
//    Example: 'pcileech.exe dump -kmd 0x...'
//  - It's possible to remove the kernel module by running 'rmmod pcileech_kmd'
//

#include <linux/module.h>
#include <linux/kallsyms.h>
#include <linux/highmem.h>
#include <linux/kthread.h>

const char LINUX_X64_STAGE3_PRE_BIN[] = {
  0xeb, 0x07, 0x6d, 0x73, 0x6c, 0x65, 0x65, 0x70, 0x00, 0x48, 0x8d, 0x3d,
  0xf2, 0xff, 0xff, 0xff, 0x48, 0x8d, 0x05, 0xf9, 0xef, 0xff, 0xff, 0x48,
  0x8b, 0x00, 0xff, 0xd0, 0x48, 0xc7, 0xc7, 0x64, 0x00, 0x00, 0x00, 0xff,
  0xd0, 0x48, 0x8d, 0x05, 0xcc, 0xff, 0xff, 0xff, 0x48, 0x8b, 0x00, 0x48,
  0x83, 0xf8, 0x00, 0x74, 0xd4
};

#define KMDDATA_MAGIC_PARTIAL			0xff11337711333388
#define KMDDATA_OPERATING_SYSTEM_LINUX		0x02

static int __init pcileech_init(void)
{
	uint64_t pg_pa, pg_va, h_thread;
	struct page *pg = alloc_pages_current(0x14, 2);
	if(!pg) {
		printk("pcileech: error allocating memory\n");
		return 1;
	}
	pg_pa = (uint64_t)page_to_phys(pg);
	pg_va = (uint64_t)phys_to_virt(pg_pa);
	set_memory_x(pg_va, 2);
	memset((void*)pg_va, 0, 0x2000);
	memcpy((void*)(pg_va + 0x1000), LINUX_X64_STAGE3_PRE_BIN, sizeof(LINUX_X64_STAGE3_PRE_BIN));
	h_thread = (uint64_t)kthread_create_on_node((void*)(pg_va + 0x1000), 0, -1, "pcileech");
	if((h_thread == -ENOMEM) || (h_thread == -EINTR)) {
		printk("pcileech: error creating thread\n");
		return 1;
	}
	*(uint64_t*)(pg_va + 0x000) = KMDDATA_MAGIC_PARTIAL;
	*(uint64_t*)(pg_va + 0x010) = (uint64_t)kallsyms_lookup_name;
	*(uint64_t*)(pg_va + 0x050) = KMDDATA_OPERATING_SYSTEM_LINUX;
	*(uint64_t*)(pg_va + 0x058) = h_thread;
	wake_up_process((struct task_struct*)h_thread);
	printk("pcileech: success - kmd loaded at address: 0x%016llX\n", pg_pa);
	return 0;
}

module_init(pcileech_init);

static void __exit pcileech_exit(void)
{
	printk("pcileech: exit\n");
}

module_exit(pcileech_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ulf Frisk");
MODULE_DESCRIPTION("pcileech.ko");
MODULE_VERSION("pcileech.ko");
