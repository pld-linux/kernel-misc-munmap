/*
 * Hotfix for do_munmap() vulnerability in <=2.4.24 and other kernels.
 *
 * Every mremap() called after creating more than 10000 VMAs will fail.
 *
 * (C) Copyright 2004 Wojtek Kaniewski <wojtekka@irc.pl>
 *     GPLv2, NO WARRANTY OF ANY KIND.
 *
 * gcc -Wall -O3 -fomit-frame-pointer -c mremap.c
 */

#include <linux/autoconf.h>
#ifdef CONFIG_SMP
#define __SMP__
#endif

#define MODULE
#define __KERNEL__
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/mman.h>
#include <linux/mm.h>
#include <asm/unistd.h>

#ifdef MODULE_LICENSE
MODULE_LICENSE("GPL");
#endif

extern void *sys_call_table[];
static unsigned long (*old_mremap)(unsigned long, unsigned long, unsigned long, unsigned long, unsigned long);

static unsigned long new_mremap(unsigned long addr, unsigned long old_len, unsigned long new_len, unsigned long flags, unsigned new_addr)
{
	struct vm_area_struct *vm;
	int count;

	for (vm = current->mm->mmap, count = 0; vm; vm = vm->vm_next) {
		if (count++ > 10000) {
			printk("possible do_munmap() exploit attempt, over 10000 vmas. uid=%d, comm=\"%.100s\"\n", current->uid, current->comm);
			return -EINVAL;
		}
	}

	return old_mremap(addr, old_len, new_len, flags, new_addr);
}

int init_module()
{
	unsigned long flags;

	save_flags(flags);
	cli();

	old_mremap = sys_call_table[__NR_mremap];
	sys_call_table[__NR_mremap] = new_mremap;
  
	restore_flags(flags);

	return 0;
}

void cleanup_module()
{
	unsigned long flags;

	save_flags(flags);
	cli();

	sys_call_table[__NR_mremap] = old_mremap;

	restore_flags(flags);
}


