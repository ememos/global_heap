// SPDX-License-Identifier: GPL-2.0
/*
 * linux/mm/global_heap.c
 *
 * Copyright(C) 2020 Electronics and Telecommunications Research Institute
 *
 * This code was inspired by Smejkal & Benatto's First Class Virtual Address Spaces, and
 * was developed based on some of their codes
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 */


#include <linux/global_heap.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/ktime.h>
#include <linux/mempolicy.h>
#include <linux/mm.h>
#include <linux/mmu_context.h>
#include <linux/rmap.h>
#include <linux/slab.h>
#include <linux/printk.h>
#include <linux/errno.h>
#include <linux/rbtree.h>
#include <linux/rwsem.h>
#include <linux/spinlock.h>
#include <linux/vmacache.h>
#include <linux/syscalls.h>
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#include <linux/string.h>
#include <linux/fcntl.h>
#include <linux/fs.h>
#include <linux/limits.h>

#include "internal.h"

#ifdef CONFIG_GLOBAL_HEAP

static struct kmem_cache *global_heap_info_cachep;

static struct global_heap_info *global_heap_desc;

#define safe_next_v(v) ((v) ? (v)->vm_next : NULL)

static void print_global_heap_metadata(struct mm_struct *mm) 
{
	int i = 0;
	struct vm_area_struct *v;

	printk("---------------- MM (%#lx) ----------------\n", mm);
	printk("PGD       : %#lx\n", pgd_val(*mm->pgd));
	printk("task size : %#lx\n", mm->task_size);
	printk("map count : %d\n", mm->map_count);
	printk("updated   : %lld\n", mm->global_heap_update);
	printk("code      : (%#lx, %#lx)\n", mm->start_code, mm->end_code);
	printk("data      : (%#lx, %#lx)\n", mm->start_data, mm->end_data);
	printk("heap      : (%#lx, %#lx)\n", mm->start_brk, mm->brk);
	printk("stack     : (%#lx)\n", mm->start_stack);
	printk("argument  : (%#lx, %#lx)\n", mm->arg_start, mm->arg_end);
	printk("environ.  : (%#lx, %#lx)\n", mm->env_start, mm->env_end);

	for (v = mm->mmap; v; v = v->vm_next, i++) {

		if (is_stack_mapping(v->vm_flags)) {
			printk(" %d] stack : (%#lx, %#lx)\n", i, v->vm_start, v->vm_end);
		}
		else if (is_data_mapping(v->vm_flags)) {
			printk(" %d] data  : (%#lx, %#lx)\n", i, v->vm_start, v->vm_end);
		} 
		else if (is_exec_mapping(v->vm_flags)) {
			printk(" %d] exec  : (%#lx, %#lx)\n", i, v->vm_start, v->vm_end);
		}
		else {
			printk(" %d] other : (%#lx, %#lx)\n", i, v->vm_start, v->vm_end);
		}

		printk("     [%c%c%c%c]\n", 
			v->vm_flags & VM_READ ? 'r' : '-',
                        v->vm_flags & VM_WRITE ? 'w' : '-',
                        v->vm_flags & VM_EXEC ? 'x' : '-',
                        v->vm_flags & VM_MAYSHARE ? 's' : 'p');

		if (v->vm_file) {
                        char *buf;

                        buf = kmalloc(PATH_MAX, GFP_KERNEL);
                        if (buf) {
                                char *ptr;
                                ptr = file_path(v->vm_file, buf, PATH_MAX);
                                if (IS_ERR(ptr)) {
                                	printk("    ??? @%lu\n", v->vm_pgoff);
				} else {
                                	printk("    %s  @%lu\n", ptr, v->vm_pgoff);
				}
                                kfree(buf);
                        } else {
                                printk("    NOT AVAILABLE @%lu\n", v->vm_pgoff);
                        }
                } else if (v->vm_ops && v->vm_ops->name) {
                        printk("     %s\n", v->vm_ops->name(v));
                } else {
                        printk("     ANONYMOUS\n");
                }

	}
}

static int is_pure_heap(struct mm_struct *mm, struct vm_area_struct *v)
{
	// reference: fs/proc/task_mmu.c/show_map_vma()
	if (v->vm_start <= mm->brk &&
	    v->vm_end >= mm->start_brk) {
		return 1; // heap
	}

	return 0;
}


/* 
 * TODO: 
 *
 * It is difficult to identify the extended heap boundary where the mmap()-allocated space can reside.
 * Currently, the boundary where the library-related segment first appears in the address space is 
 * 	regarded as the end of the heap temporarily.
 * However, some modifications are required depending on the OS version and the type of library to be linked.
 * */
static int is_first_lib_under_stack(struct mm_struct *mm, struct vm_area_struct *v)
{
	struct vm_area_struct *n1 = v->vm_next;
	struct vm_area_struct *n2;

	if (v->vm_start <= mm->brk) {
		goto out;
	}

#if 1
	if (is_exec_mapping(v->vm_flags)) {
		return 1;
	}
#endif

	if (n1 == NULL) {
		goto out;
	}

#if 2
	if (is_exec_mapping(n1->vm_flags)) {
		return 1;
	}
#endif

	n2 = n1->vm_next;

	if (n2 == NULL) {
		goto out;
	}

	if (is_exec_mapping(n2->vm_flags)) {
		return 1;
	}

out:
	return 0;
}

static int is_code(struct mm_struct *mm, struct vm_area_struct *v)
{
	if ((v->vm_start >= round_down(mm->start_code, PAGE_SIZE)) &&
                (v->vm_end <= round_up(mm->end_code, PAGE_SIZE))) {
                return 1;
        }

	return 0;
}

#if 0

// TODO: function to skip heap vma made by brk/mmap ?
static int is_heap(struct mm_struct *mm, struct vm_area_struct *v)
{
#if 0
	if ((v->vm_start >= round_down(mm->start_brk, PAGE_SIZE)) &&
		(v->vm_end <= round_up(mm->start_stack, PAGE_SIZE))) {
		return 1;
	}
#else
	// reference: fs/proc/task_mmu.c/show_map_vma()
	if (v->vm_start <= mm->brk &&
	    v->vm_end >= mm->start_brk) {
		return 1; // heap
	}
#endif

	return 0;
}
#endif

static int remove_v(struct mm_struct *mm, struct vm_area_struct *v)
{
	int ret = 0;

#if 0
	ret = do_munmap(mm, v->vm_start, v->vm_end - v->vm_start, NULL);
#else

	size_t len = (size_t)(v->vm_end - v->vm_start);

#ifdef CONFIG_GLOBAL_HEAP_DEBUG
	printk("remove_v: remove vma(start:%#lx - end:%#lx, len:%lu) from mm[%#lx]\n", v->vm_start, v->vm_end, len, mm);
#endif

	ret = do_munmap(mm, v->vm_start, len, NULL);

#endif


	return ret;
}


//
// Before calling this function, semaphore must be taken
//
static struct vm_area_struct *copy_v(struct mm_struct *mm_from, struct vm_area_struct *v_from, struct mm_struct *mm_to, unsigned long vmflags, int to_replicate)
{
	struct vm_area_struct *prev;
	struct rb_node **rb_link;
	struct rb_node *rb_parent;
	struct vm_area_struct *v_to;

#ifdef CONFIG_GLOBAL_HEAP_DEBUG
	printk("copy_v: copy vma(start:%#lx - end:%#lx) ==> %#lx\n", v_from->vm_start, v_from->vm_end, mm_to);
#endif

	if (find_vma_links(mm_to, v_from->vm_start, v_from->vm_end, &prev, &rb_link, &rb_parent) < 0) {
		printk(KERN_ERR "copy_v: cannot find_vma_links\n");
		goto out;
	}

	v_to = vm_area_dup(v_from);
	if (!v_to) {
		goto out;
	}

	if (vma_dup_policy(v_from, v_to)) {
		goto out_free_v;
	}

	if (anon_vma_clone(v_to, v_from)) {
		goto out_free_mempol;
	}

	v_to->vm_mm = mm_to;
	v_to->vm_flags = vmflags;
	vma_set_page_prot(v_to);
	v_to->vm_next = NULL;
       	v_to->vm_prev = NULL;

	if (v_to->vm_file) {
		get_file(v_to->vm_file);
	}

	if (v_to->vm_ops && v_to->vm_ops->open) {
		v_to->vm_ops->open(v_to);
	}

	v_to->global_heap_update = v_from->global_heap_update;

	vma_link(mm_to, v_to, prev, rb_link, rb_parent);

	vm_stat_account(mm_to, v_to->vm_flags, vma_pages(v_to));

	if (to_replicate) {
		//if ( unlikely(replicate_page_range(mm_to, v_to, mm_from, v_from))) {
		if (replicate_page_range(mm_to, v_to, mm_from, v_from)) {
			printk(KERN_ERR "copy_v: replicate_page_range failed : vma(%#lx) ==> vma(%#lx)\n", v_from, v_to);
		}
	}

	return v_to;

out_free_mempol:
	mpol_put(vma_policy(v_to));

out_free_v:
	vm_area_free(v_to);

out:
	return NULL;
}

static struct vm_area_struct *safe_copy_v(struct mm_struct *mm_from, struct vm_area_struct *v_from, struct mm_struct *mm_to, unsigned long vmflags, int to_replicate)
{
	struct vm_area_struct *v = NULL;
	struct vm_area_struct *v_to = NULL;

#ifdef CONFIG_GLOBAL_HEAP_DEBUG
        printk("safe_copy_v: safe copy_v from vma(start:%#lx - end:%#lx) ==> mm_to(%#lx)\n", v_from->vm_start, v_from->vm_end, mm_to);
#endif

	v = find_vma(mm_to, v_from->vm_start); 

	// v is NULL
	if (!v) {
		v_to = copy_v(mm_from, v_from, mm_to, v_from->vm_flags, 1);
	        if (!v_to) {
			goto out;
		}
	} else {
		if ((v->vm_start > v_from->vm_end) || (v->vm_end < v_from->vm_start)) {
			v_to = copy_v(mm_from, v_from, mm_to, v_from->vm_flags, 1);
	        	if (!v_to) {
				goto out;
			}
		} else {
        		printk("safe_copy_v: vma overlapping! [start:%#lx - end:%#lx] <-> [start:%#lx - end:%#lx]\n", v_from->vm_start, v_from->vm_end, v->vm_start, v->vm_end);
		}
	}

out:
	return v_to;
}


static struct vm_area_struct *update_v(struct mm_struct *mm_from, struct vm_area_struct *v_from, struct mm_struct *mm_to, struct vm_area_struct *v_to)
{
	struct vm_area_struct *v = NULL;

#ifdef CONFIG_GLOBAL_HEAP_DEBUG
        printk("update_v: update from vma(start:%#lx - end:%#lx) ==> mm_to(%#lx)\n", v_from->vm_start, v_from->vm_end, mm_to);
#endif


	// v_to is NULL 
	if (!v_to) {
		v = find_vma(mm_to, v_from->vm_start); // find source vma from destination mm
		if (!v) {
#ifdef CONFIG_GLOBAL_HEAP_DEBUG
			printk("update_v: no vma in destination mm!\n");
#endif
			v_to = NULL;
			goto out;
		} else {
			if (v->vm_start == v_from->vm_start && v->vm_end == v_from->vm_end) {  
				v_to = v;
			} else if (v->vm_start != v_from->vm_start && v->vm_end == v_from->vm_end 
			     	&& v_from->vm_flags & VM_GROWSDOWN) {
			        v_to = v; 	// stack
			} else {
#ifdef CONFIG_GLOBAL_HEAP_DEBUG
				printk("update_v: no vma in destination mm!!\n");
#endif
				v_to = NULL;
				goto out;
			}

		}
	}

	if (ktime_compare(v_from->global_heap_update, v_to->global_heap_update) == 0) {
#ifdef CONFIG_GLOBAL_HEAP_DEBUG
		printk("update_v: unchanged !\n");
#endif
		goto out;
	} 
	else if (ktime_compare(v_from->global_heap_update, v_to->global_heap_update) == -1) {
#ifdef CONFIG_GLOBAL_HEAP_DEBUG
		printk("update_v: stale (from:%lld, to:%lld) !\n", v_from->global_heap_update, v_to->global_heap_update);
#endif
		v_to = NULL;
		goto out;
	} 
	// vma found
	else if ((v_from->vm_start != v_to->vm_start) || (v_from->vm_end != v_to->vm_end)) {

		if (remove_v(mm_to, v_to) < 0) {
			v_to = NULL;
			goto out;
		}

		v_to = copy_v(mm_from, v_from, mm_to, v_from->vm_flags, 1);
		if (!v_to) {
			goto out;
		}

	} else {
		if ( unlikely(replicate_page_range(mm_to, v_to, mm_from, v_from))) {
			printk(KERN_ERR "update_v: replicate_page_range failed : vma(%#lx) ==> vma(%#lx) s\n", v_from, v_to);
		}
		v_to->global_heap_update = v_from->global_heap_update;
	}

out:
	return v_to;
}

static int register_global_heap_desc(int heap_id, struct mm_struct *mm_next, struct task_struct *task, OTHER_THAN_HEAP_STATUS st)
{
	int ret = 0;

#ifdef CONFIG_GLOBAL_HEAP_DEBUG
	printk("register_global_heap_desc: new mm_struct(%#lx) ==>  global_heap_desc->info[%d].global_heap_entry\n", mm_next, heap_id);
#endif

	spin_lock(&global_heap_desc->global_heap_lock);

	if (global_heap_desc->info[heap_id].global_heap_entry == NULL) {
		global_heap_desc->info[heap_id].global_heap_entry = mm_next;
		global_heap_desc->info[heap_id].pid = task->pid;
		global_heap_desc->info[heap_id].status = st;
	} else {
		printk(KERN_ERR "register_global_heap_desc: already occupied in global_heap_desc->info[%d].global_heap_entry\n", heap_id);
		ret = -EINVAL;
		goto out;
	}

out:
	spin_unlock(&global_heap_desc->global_heap_lock);

	return ret;
}

static int update_global_heap_desc(int heap_id, struct mm_struct *mm_next, struct task_struct *task, OTHER_THAN_HEAP_STATUS st)
{
	int ret = 0;

#ifdef CONFIG_GLOBAL_HEAP_DEBUG
	printk("update_global_heap_desc(status:%d): existing mm_struct(%#lx) - global_heap_desc->info[%d].global_heap_entry:%#lx\n", st, mm_next, heap_id, global_heap_desc->info[heap_id].global_heap_entry);
#endif

	spin_lock(&global_heap_desc->global_heap_lock);

	if (global_heap_desc->info[heap_id].global_heap_entry == mm_next) {
		global_heap_desc->info[heap_id].pid = task->pid;
		global_heap_desc->info[heap_id].status = st;
	} else {
		printk(KERN_ERR "update_global_heap_desc: not existing global_heap_desc->info[%d].global_heap_entry: %#lx\n", heap_id, global_heap_desc->info[heap_id].global_heap_entry);
		ret = -EINVAL;
		goto out;
	}

out:
	spin_unlock(&global_heap_desc->global_heap_lock);

	return ret;

}


// TODO
// This function has to be called with semaphores for related mm_struct stuctures held
static int remove_other_than_global_heap(int heap_id, struct mm_struct *mm_old, struct mm_struct *mm_next) 
{
	int ret = 0;
	struct vm_area_struct *v;
	struct vm_area_struct *next;
	unsigned long first_lib_under_stack = 0UL;
	int cnt = 0;

	for (v = mm_next->mmap, next = safe_next_v(v); v; v = next, next = safe_next_v(next)) {

		if (first_lib_under_stack) {
			remove_v(mm_next, v); // remove other areas including libraries and above
			cnt++;
			continue;	
		} 
#if 0
		else if (is_code(mm_next, v)) {
			remove_v(mm_next, v); // remove code areas
			cnt++;
			continue;
		} 
#endif
		else if (is_pure_heap(mm_next, v)) {
			// pure heap : do not remove !
			continue;
		} else if (!first_lib_under_stack) {

#if 0
			if (v->vm_end < mm_next->start_brk) {
				continue; // preserve data areas
			}
#endif

			if (v->vm_start > mm_next->brk
				&& v->vm_start < mm_next->start_stack
				&& is_first_lib_under_stack(mm_next, v)) {

				first_lib_under_stack = v->vm_start;
#ifdef CONFIG_GLOBAL_HEAP_DEBUG
				printk("... remove_other_than_global_heap: first_lib_under_stack detected, v->vm_start[%#lx] !!! \n", v->vm_start);
#endif
			}

			if (v->vm_start > mm_next->brk
				&& v->vm_start < mm_next->start_stack
				&& !first_lib_under_stack) {
				// mmap  range : do not remove !
				continue;
			}
			remove_v(mm_next, v); // remove code, data
			cnt++;
		}
	}

#ifdef CONFIG_GLOBAL_HEAP_DEBUG
        printk("remove_other_than_global_heap: in global heap(%d), %d vmareas deleted! \n", heap_id, cnt);
#endif


out:
	return ret;
}	


// TODO
static int sync_before_switch(int heap_id, struct mm_struct **mm_old, struct mm_struct **mm_next)
{
	int ret = 0;
	struct vm_area_struct *v;
	struct vm_area_struct *next;
	int first = 0;
	int once_1 = 1;
	int once_2 = 1;
#if 0
	int remove_except_global_heap_flag = 0;
#endif
	int to_replicate;
	unsigned long first_lib_under_stack;

#ifdef CONFIG_GLOBAL_HEAP_DEBUG
	printk("sync_before_switch(heap_id:%d) is called => mm_old:%#lx, mm_next:%#lx\n", heap_id, *mm_old, *mm_next);
#endif


	if (*mm_old == NULL) {
		printk(KERN_ERR "sync_before_switch: Switching from NULL process\n");
		ret = -1;
		goto out;
	}

	if (*mm_next == NULL) {
		// TODO: Does it work?
		//
		// Currently, allocate_mm() then mm_init()
		// 
		// TODO: Consider revising mm_init() ==> mm_setup, mm_set_task style ?
		//
		*mm_next = mm_alloc(); // allocate_mm() & mm_init()
		if (!(*mm_next)) {
			printk(KERN_ERR "sync_before_switch: failed to mm_alloc\n");
			ret = -1;
			goto out;
		}

#ifdef CONFIG_GLOBAL_HEAP_DEBUG
		printk("sync_before_switch(): mm_alloc --> mm_next(%#lx)\n", *mm_next);
#endif

		// TODO: ? arch_pick_mmap_layout
		(*mm_next)->mmap_base = (*mm_old)->mmap_base;
		(*mm_next)->mmap_legacy_base = (*mm_old)->mmap_legacy_base;
		(*mm_next)->get_unmapped_area = (*mm_old)->get_unmapped_area;

		set_mm_exe_file(*mm_next, get_mm_exe_file(*mm_old));
		(*mm_next)->global_heap_update = (*mm_old)->global_heap_update;
		first = 1; 

		register_global_heap_desc(heap_id, *mm_next, current, OTHS_VALID);
	}


	// TODO: lock
	if (down_write_killable(&(*mm_next)->mmap_sem)) {
		ret = -EINTR;
		goto out;
	}

	down_read_nested(&(*mm_old)->mmap_sem, SINGLE_DEPTH_NESTING);
	
	first_lib_under_stack = 0UL;

	//for (v = (*mm_old)->mmap; v; v = v->vm_next) {
	for (v = (*mm_old)->mmap, next = safe_next_v(v); v; v = next, next = safe_next_v(next)) {
#if 0
		// is_heap: if heap ==> return 0
		if (is_heap(*mm_old, v)){
			// if heap, not replicate page entries
			to_replicate = 0;
#ifdef CONFIG_GLOBAL_HEAP_DEBUG
			printk("sync_before_switch: vma[%#lx-%#lx] is heap --> skip!\n", v->vm_start, v->vm_end);
#endif
		} else {
			to_replicate = 1; // not heap
		}
#else
		if (first_lib_under_stack) {

			to_replicate = 1;
		}
#if 0
		else if (is_code(*mm_old, v)) {
			to_replicate = 1;
		}

#endif
		else if (is_pure_heap(*mm_old, v)){

			to_replicate = 0; // pure heap : not replicate page entries

		}  else if (!first_lib_under_stack) {

#if 0
			if (v->vm_end < (*mm_old)->start_brk) {
				to_replicate = 2; // preserve data areas
			} else {
				to_replicate = 1;

			}
#else
			to_replicate = 1;
#endif

			if (v->vm_start > (*mm_old)->brk
				&& v->vm_start < (*mm_old)->start_stack
				&& is_first_lib_under_stack(*mm_old, v)) {

				first_lib_under_stack = v->vm_start;
#ifdef CONFIG_GLOBAL_HEAP_DEBUG
				printk("### sync_before_switch: first_lib_under_stack detected, v->vm_start[%#lx] !!! \n", v->vm_start);
#endif
			}

			if (v->vm_start > (*mm_old)->brk
				&& v->vm_start < (*mm_old)->start_stack
				&& !first_lib_under_stack) {
				
				// ex. mmap : not replicate page entries & vma
				to_replicate = 0; // when !first_lib_under_stack 
			}
		}
#endif

		// CASE: first switch into the NULL global heap
		if (first) {
			if (v->vm_start > (*mm_old)->brk
				&& !first_lib_under_stack && !to_replicate){
				// when mmap case above mm->brk,
				// 	copy_v is not called
				continue; 
			} else {
				// when pure heap, 
				// 	even the value zero of variable 'to_replicate'
				// 	 is trasferred to copy_v
				// and any other case, copy_v is called

#if 0
				if (to_replicate == 2) {
					to_replicate = 1;
				}
#endif

				// copy mm_old's vm_area_struct into mm_next
				copy_v(*mm_old, v, *mm_next, v->vm_flags, to_replicate);
				continue;
			} 

		}
	       
		// CASE: switch into the existing global heap

		// switching between identical processes
#if 0
		//if (current == global_heap_desc->last_owner[heap_id] &&
		//	global_heap_desc->status[heap_id] == OTHS_VALID) {	
		if (current->pid == global_heap_desc->pid[heap_id] &&
			global_heap_desc->status[heap_id] == OTHS_VALID) {	
#else
		if (current->pid == global_heap_desc->info[heap_id].pid &&
			global_heap_desc->info[heap_id].status == OTHS_VALID) {	
#endif

			// TODO:
			/* if to_replicate == 2, does not update_v */

			if (to_replicate == 1) {
				// update mm_next's vm_area_struct from the mm_old's
				update_v(*mm_old, v, *mm_next, NULL); // TODO
			}


		} else {
			// switching between different processes
#if 0
			printk(KERN_ERR "sync_before_switch(): different processes not yet supported!\n");
			ret = -1;
			goto out;
#else
			// TODO: 

			if (once_1) {
				if ((*mm_old)->start_brk > (*mm_next)->start_brk) {
					printk(KERN_ERR "sync_before_switch(): does not support a specific placement in switching between different processes! [old(%#lx) -- next(%#lx)]\n", (*mm_old)->start_brk, (*mm_next)->start_brk);
					ret = -1;
					goto unlock_out;
				}


				if (remove_other_than_global_heap(heap_id, *mm_old, *mm_next) < 0) {
					printk(KERN_ERR "sync_before_switch(): remove_other_than_global_heap failed\n");
					ret = -1;

					update_global_heap_desc(heap_id, *mm_next, current, OTHS_INTERMEDIATE);
					goto unlock_out;
				}

				once_1 = 0;
#if 0
				remove_except_global_heap_flag = 1;
#endif

				update_global_heap_desc(heap_id, *mm_next, current, OTHS_CLEANED);
			}

			if (to_replicate == 1) {
				if (safe_copy_v(*mm_old, v, *mm_next, v->vm_flags, to_replicate) ==  NULL) {

					printk(KERN_ERR "sync_before_switch(): does not support safe_copy_v [%#lx-%#lx]!\n", v->vm_start, v->vm_end);
					ret = -1;
					goto unlock_out;
				}

				if (once_2) {
					update_global_heap_desc(heap_id, *mm_next, current, OTHS_INTERMEDIATE);
					once_2 = 0;
				}
			}

			if (v->vm_next == NULL) {
				update_global_heap_desc(heap_id, *mm_next, current, OTHS_VALID);
			}
#endif
		}
	}

	if (first) {
		(*mm_next)->start_code = (*mm_old)->start_code;
		(*mm_next)->end_code = (*mm_old)->end_code;
		(*mm_next)->start_data = (*mm_old)->start_data;
		(*mm_next)->end_data = (*mm_old)->end_data;
		(*mm_next)->start_brk = (*mm_old)->start_brk;
		(*mm_next)->brk = (*mm_old)->brk;
		(*mm_next)->start_stack = (*mm_old)->start_stack;
		(*mm_next)->arg_start = (*mm_old)->arg_start;
		(*mm_next)->arg_end = (*mm_old)->arg_end;
		(*mm_next)->env_start = (*mm_old)->env_start;
		(*mm_next)->env_end = (*mm_old)->env_end;
		(*mm_next)->task_size  = (*mm_old)->task_size;
	}
#if 0
	else if (remove_except_global_heap_flag) {
#else
	else {
#endif
		(*mm_next)->start_code = (*mm_old)->start_code;
		(*mm_next)->end_code = (*mm_old)->end_code;
		(*mm_next)->start_data = (*mm_old)->start_data;
		(*mm_next)->end_data = (*mm_old)->end_data;

		// both brk and start_brk in mm_next are already valid
		
		(*mm_next)->start_stack = (*mm_old)->start_stack;
		(*mm_next)->arg_start = (*mm_old)->arg_start;
		(*mm_next)->arg_end = (*mm_old)->arg_end;
		(*mm_next)->env_start = (*mm_old)->env_start;
		(*mm_next)->env_end = (*mm_old)->env_end;
		(*mm_next)->task_size  = (*mm_old)->task_size;
	}

#ifdef CONFIG_GLOBAL_HEAP_DEBUG
	print_global_heap_metadata(*mm_next);
#endif

unlock_out:
	up_read(&(*mm_old)->mmap_sem);
	up_write(&(*mm_next)->mmap_sem);

out:
	return ret;
}

// TODO
static int remove_vmas(int heap_id, struct mm_struct *mm)
{
	int ret = 0;
	struct vm_area_struct *v;
	struct vm_area_struct *next;

	if (down_write_killable(&mm->mmap_sem)) {
		ret = -EINTR;
		goto out;
	}

	for (v = mm->mmap, next = safe_next_v(v); v; v = next, next = safe_next_v(next)) {
		if (remove_v(mm, v) < 0) {
			printk(KERN_ERR "remove_vmas: remove_v(mm:%#lx, [%#lx - %#lx]) failed\n", mm, v->vm_start, v->vm_end);
		}
	}

	up_write(&mm->mmap_sem);

out:
	return ret;
}


static int find_mm(int heap_id, struct task_struct *task, struct mm_struct **mm_next, struct mm_struct **mm_old)
{
	int ret = 0;
#ifdef CONFIG_GLOBAL_HEAP_DEBUG
	printk( "find_mm: Switching from [heap:%d] to [heap:%d], task(%#lx)\n", task->current_global_heap, heap_id, task);
#endif

	spin_lock (&global_heap_desc->global_heap_lock);

	// initial owner
#if 0
	if (task->current_global_heap == 0){
#else
	if (task->current_global_heap == 0 
		&& global_heap_desc->info[0].global_heap_entry == NULL) {
#endif
		global_heap_desc->info[0].global_heap_entry = task->orig_mm;
			// heap 0 must not be used as global heap
		
		global_heap_desc->info[0].pid = task->pid;
		global_heap_desc->info[0].status = OTHS_VALID;
	}

	// Find source mm_struct
#if 0
	if (task->current_global_heap == 0) {
		//The slot of global_heap_desc->global_heap_entry[0] is not used
		*mm_old = task->orig_mm;

	} else {
		*mm_old = global_heap_desc->global_heap_entry[task->current_global_heap];
	}
#else
	*mm_old = global_heap_desc->info[task->current_global_heap].global_heap_entry;
#endif

	// Find destination mm_struct
#if 0
	if (heap_id == 0) {
		//The slot of global_heap_desc->global_heap_entry[0] is not used
		*mm_next = task->orig_mm;
	} else {
		*mm_next = global_heap_desc->global_heap_entry[heap_id];
	}
#else
	*mm_next = global_heap_desc->info[heap_id].global_heap_entry;
#endif

	// TODO: null processing: mm_old, mm_next ?
	
#ifdef CONFIG_GLOBAL_HEAP_DEBUG
	printk( "find_mm(heap_id:%d) ==> found mm_old(%#lx), mm_next(%#lx)\n", heap_id, *mm_old, *mm_next);
#endif

	spin_unlock (&global_heap_desc->global_heap_lock);

	return ret;
}


int __init global_heap_init(void)
{
	int i;
	int ret = 0;

	//global_heap_info_cachep = KMEM_CACHE(global_heap_info, SLAB_PANIC|SLAB_NOTRACK);
	global_heap_info_cachep = KMEM_CACHE(global_heap_info, SLAB_PANIC);


	global_heap_desc = kmem_cache_zalloc(global_heap_info_cachep, GFP_KERNEL);
	if (!global_heap_desc) {
		printk(KERN_ERR "global_heap_init: fail to kem_cache_zalloc\n");
		ret = -ENOMEM;
		goto out;
	}

	spin_lock_init(&global_heap_desc->global_heap_lock);		

	for (i = 0; i < NUM_GLOBAL_HEAPS; i++) {
		global_heap_desc->info[i].global_heap_entry = NULL;
		global_heap_desc->info[i].pid = -1;
		global_heap_desc->info[i].status = OTHS_CLEANED;
		memset(global_heap_desc->info[i].private, 0, 2048);
	}

out:
	return ret;
}


int global_heap_switch(struct task_struct *task, int heap_id)
{
	int ret = 0;
	struct mm_struct *mm_next;
	struct mm_struct *mm_old;
	//struct mm_struct *mm_active;

#ifdef CONFIG_GLOBAL_HEAP_DEBUG
	printk("global_heap_switch is called(task:%#lx, heap: %d -> %d)\n", task, task->current_global_heap, heap_id);
#endif
	if (heap_id < 0 || heap_id > (NUM_GLOBAL_HEAPS-1)) {
		printk(KERN_ERR "global_heap_switch(=>heap_id: %d): invalid heap ID\n", heap_id);
		ret = -EINVAL;
		goto out;
	}

	if (!task) {
		printk(KERN_ERR "global_heap_switch(=>heap_id: %d): task argument is NULL\n", heap_id);
		ret = -EINVAL;
		goto out;
	}

	ret = find_mm(heap_id, task, &mm_next, &mm_old);
	if (ret < 0) {
		printk(KERN_ERR "global_heap_switch: find_mm failed\n");
		goto out;
	}
	
	if (mm_old == mm_next) {
		printk("global_heap_switch(heap_id:%d): mm_old(%#lx) == mm_next(%#lx)\n", heap_id, mm_old, mm_next);
		ret = 0;
		goto out;
	}

	sync_mm_rss(task->mm);

	// prepare_switch
	ret = sync_before_switch(heap_id, &mm_old, &mm_next);
	if (ret < 0) {
		printk(KERN_ERR "fail to sync before switch (heap: %d -> %d)\n", task->current_global_heap, heap_id);
		goto out;
	}
	

	task_lock(task);

	vmacache_flush(task);
	switch_mm(mm_old, mm_next, task);
#ifdef CONFIG_GLOBAL_HEAP_DEBUG
	printk("global_heap_switch: switch_mm(mm_old: %#lx, mm_next: %#lx, task:%#lx) is called\n", mm_old, mm_next, task);
#endif

	//mm_active = task->active_mm;
	//if (mm_active != mm_next) {
	//	task->active_mm = mm_next;
	//}
	task->mm = mm_next;
	task->active_mm = mm_next;
	task->current_global_heap = heap_id;

	task_unlock(task);

out:
	return ret;
}
EXPORT_SYMBOL(global_heap_switch);

int global_heap_exit(struct task_struct *task)
{
	int ret = 0;

	if (task->current_global_heap != 0) {

		if((ret = global_heap_switch(task, 0)) < 0) {
			printk(KERN_ERR "global_heap_exit: fail to global_heap_switch(0) ->%d\n", ret);
		}
	}

	spin_lock(&global_heap_desc->global_heap_lock);

	global_heap_desc->info[0].global_heap_entry = NULL;
	global_heap_desc->info[0].pid = -1;
	global_heap_desc->info[0].status = OTHS_CLEANED;
	memset(global_heap_desc->info[0].private, 0, 2048);

	spin_unlock(&global_heap_desc->global_heap_lock);

	// TODO: future additional global_heap cleaning?
	
	return ret;
}

int global_heap_print_metadata(int heap_id)
{
	int ret = 0;

	spin_lock(&global_heap_desc->global_heap_lock);

        if (global_heap_desc->info[heap_id].global_heap_entry == NULL) {
                printk( "---------------- global heap entry [%d] ---------------- \n", heap_id);
                printk( "	 ==> NULL\n");
	} else {
                printk( "---------------- global heap entry [%d] ---------------- \n", heap_id);
		print_global_heap_metadata( global_heap_desc->info[heap_id].global_heap_entry);
        }

out:
	spin_unlock(&global_heap_desc->global_heap_lock);

	return ret;
}
EXPORT_SYMBOL(global_heap_print_metadata);

int global_heap_remove(int heap_id)
{
	int ret = 0;
	struct mm_struct *mm;

#ifdef CONFIG_GLOBAL_HEAP_DEBUG
	printk("global_heap_remove is called(heap: %d)\n", heap_id);
#endif

	spin_lock(&global_heap_desc->global_heap_lock);

	if (global_heap_desc->info[heap_id].global_heap_entry != NULL) {
		mm = global_heap_desc->info[heap_id].global_heap_entry;

		remove_vmas(heap_id, mm);
	
		global_heap_desc->info[heap_id].global_heap_entry = NULL;
		global_heap_desc->info[heap_id].pid = -1;
		global_heap_desc->info[heap_id].status = OTHS_CLEANED;
		memset(global_heap_desc->info[heap_id].private, 0, 2048);

		spin_unlock(&global_heap_desc->global_heap_lock);

		__mmdrop(mm);

	} else {
		spin_unlock(&global_heap_desc->global_heap_lock);

		printk("global_heap_remove: mm is NULL\n");
		goto out;
	}

out:

	return ret;
}
EXPORT_SYMBOL(global_heap_remove);


SYSCALL_DEFINE1(global_heap_switch, int, heap_id)
{
	int ret = 0;
	struct task_struct *task = current;

	if (heap_id < 0 || heap_id > (NUM_GLOBAL_HEAPS -1)) {
		ret = -EINVAL;
		goto out;
	}

	ret = global_heap_switch(task, heap_id);

out:
	return ret;
}


SYSCALL_DEFINE3(global_heap_switch2, int, heap_id, char __user *, src, char __user *, dst)
{
	int ret = 0;
	struct task_struct *task = current;

	if (heap_id < 0 || heap_id > (NUM_GLOBAL_HEAPS -1)) {
		ret = -EINVAL;
		goto out;
	}

	if (copy_from_user(global_heap_desc->info[task->current_global_heap].private, src, 2048) != 0) {
		ret = -EFAULT;
		goto out;
	}

#ifdef CONFIG_GLOBAL_HEAP_DEBUG
	printk("global_heap_switch2: info[%d].private <== copy_from_user", task->current_global_heap);
#endif

	ret = global_heap_switch(task, heap_id);
	if (ret < 0) {
		goto out;
	}

	if (global_heap_desc->info[heap_id].global_heap_entry != NULL) {
		if (copy_to_user(dst, global_heap_desc->info[heap_id].private, 2048) != 0) {
			ret = -EFAULT;
			goto out;
		}
#ifdef CONFIG_GLOBAL_HEAP_DEBUG
		printk("global_heap_switch2: copy_to_user ==> info[%d].private", heap_id);
#endif
	} else {
		ret = -EINVAL;
		printk(KERN_ERR "global_heap_switch2: cannot copy_to_user ==> info[%d] NULL", heap_id);
		goto out;
	}

out:
	return ret;
}



SYSCALL_DEFINE1(global_heap_print_metadata, int, heap_id)
{
#if 0
	int ret = 0;
#else
	long ret = 0;
#endif

	if (heap_id < 0 || heap_id > (NUM_GLOBAL_HEAPS -1)) {
		ret = -EINVAL;
		goto out;
	}

	ret = global_heap_print_metadata(heap_id);

out:
	return ret;
}

SYSCALL_DEFINE1(global_heap_remove, int, heap_id)
{
	int ret = 0;
	struct task_struct *task = current;

	if (heap_id < 0 || heap_id > (NUM_GLOBAL_HEAPS -1)) {
		ret = -EINVAL;
		goto out;
	}

	ret = global_heap_remove(heap_id);

out:
	return ret;
}

#endif // CONFIG_GLOBAL_HEAP
