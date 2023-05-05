#pragma once

#include "penglai-enclave-page.h"
#include "buddy_struct.h"

void init_buddy(struct global_mem *zone, struct relay_page *start_page,
		vaddr_t start_addr, u64 page_num);

struct relay_page *buddy_get_pages(struct global_mem *zone, u64 order);
void buddy_free_pages(struct global_mem *zone, struct relay_page *relay_page);