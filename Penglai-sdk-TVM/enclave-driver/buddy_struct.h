/*
 * Copyright (c) 2020 Institute of Parallel And Distributed Systems (IPADS), Shanghai Jiao Tong University (SJTU)
 * OS-Lab-2020 (i.e., ChCore) is licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *   http://license.coscl.org.cn/MulanPSL
 *   THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 *   IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 *   PURPOSE.
 *   See the Mulan PSL v1 for more details.
 */

#pragma once

#include <linux/list.h>
#include <linux/types.h>

#define BUDDY_PAGE_SHIFT    (12UL)
#define BUDDY_PAGE_SIZE     (1UL << BUDDY_PAGE_SHIFT)
/* [0, BUDDY_MAX_ORDER) */
#define BUDDY_MAX_ORDER     (20UL)

struct relay_page {
	struct list_head      list_node;
	u64                   flags;
	union {
		u64           order;
		struct relay_page   *first_page;
	};
	void                  *slab;
};

struct free_list {
	struct list_head    list_head;
	u64		    nr_free;
};

struct global_mem {
	unsigned long       page_num;
	unsigned long       page_size;
	/* first_page: the start vaddr of the metadata area */
	struct relay_page         *first_page;
	/* start_addr, end_addr: the range (vaddr) of physical memory */
	unsigned long       start_addr;
	unsigned long       end_addr;
	struct free_list    free_lists[BUDDY_MAX_ORDER];
};
