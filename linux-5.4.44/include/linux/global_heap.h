#ifndef _LINUX_GLOBAL_HEAP_H
#define _LINUX_GLOBAL_HEAP_H

#include <linux/sched.h>
#include <linux/mm_types.h>
#include <linux/spinlock.h>
#include <linux/printk.h>
#include <linux/kernel.h>

#ifdef CONFIG_GLOBAL_HEAP

extern int global_heap_init(void);
extern int global_heap_exit(struct task_struct *task);
extern int global_heap_switch(struct task_struct *task, int heap_id);
extern int global_heap_print_metadata(int heap_id);
extern int global_heap_remove(int heap_id);

#endif

#endif
