#include <linux/list.h>
#include "buddy.h"

/*
 * local functions or types
 */

enum relayPageFlags {
	RPG_head,
	RPG_buddy,
};

static inline void set_page_order_buddy(struct relay_page *relay_page, u64 order)
{
	relay_page->order = order;
	relay_page->flags |= (1UL << RPG_buddy);
}

static inline void clear_page_order_buddy(struct relay_page *relay_page)
{
	relay_page->order = 0;
	relay_page->flags &= ~(1UL << RPG_buddy);
}

static inline u64 get_page_order(struct relay_page *relay_page)
{
	return relay_page->order;
}

static inline u64 get_page_idx(struct global_mem *zone, struct relay_page *relay_page)
{
	return (relay_page - zone->first_page);
}

/*
 * return the start relay_page (metadata) of the only one buddy.
 * e.g., relay_page 0 and relay_page 1 are buddies, relay_page (0, 1) and relay_page (2, 3) are buddies
 */
static inline struct relay_page *get_buddy_page(struct global_mem *zone,
					  struct relay_page *relay_page,
					  u64 order)
{
	u64 page_idx;
	u64 buddy_idx;

	page_idx = get_page_idx(zone, relay_page);
	/* find buddy index (to merge with) */
	buddy_idx = (page_idx ^ (1 << order));

	return zone->first_page + buddy_idx;
}

/* return the start relay_page (metadata) after "merging" the relay_page and its buddy */
static inline struct relay_page *get_merge_page(struct global_mem *zone,
					  struct relay_page *relay_page,
					  u64 order)
{
	u64 page_idx;
	u64 merge_idx;

	page_idx  = get_page_idx(zone, relay_page);
	merge_idx = page_idx & ~(1 << order);

	return zone->first_page + merge_idx;
}

static void split(struct global_mem *zone, struct relay_page *relay_page,
		   u64 low_order, u64 high_order,
		   struct free_list *list)
{
	u64 size;

	size = (1U << high_order);
	/* keep splitting */
	while (high_order > low_order) {
		list--;
		high_order--;
		size >>= 1;
		/* put into the corresponding free list */
		list_add(&relay_page[size].list_node, &list->list_head);
		list->nr_free++;
		// set relay_page order
		set_page_order_buddy(&relay_page[size], high_order);
	}
}

static struct relay_page *__alloc_page(struct global_mem *zone, u64 order)
{
	struct relay_page *relay_page;
	struct free_list *list;
	u64 current_order;

	/* search the free list one by one */
	for (current_order = order; current_order < BUDDY_MAX_ORDER;
	     current_order++) {
		list = zone->free_lists + current_order;
		if (list_empty(&list->list_head)) {
			continue;
		}

		/* find one and remove it from the free list */
		relay_page = list_entry(list->list_head.next, struct relay_page,
				  list_node);
		list_del(&relay_page->list_node);
		list->nr_free--;

		clear_page_order_buddy(relay_page);
		/* split and put remaining parts back to free lists */

		split(zone, relay_page, order, current_order, list);

		relay_page->order = order;
		relay_page->flags |= (1UL << RPG_head);

		return relay_page;
	}
	return NULL;
}

/* check whether the buddy can be merged */
static inline bool check_buddy(struct relay_page *relay_page, u64 order)
{
	return (relay_page->flags & (1UL << RPG_buddy))
		&& (relay_page->order == order);
}

/*
 * exported functions
 */

void init_buddy(struct global_mem *zone, struct relay_page *first_page,
		vaddr_t first_page_vaddr, u64 page_num)
{
	u64 i;
	struct relay_page *relay_page;
	struct free_list *list;


	/* init global memory metadata */
	zone->page_num = page_num;
	zone->page_size = BUDDY_PAGE_SIZE;
	zone->first_page = first_page;
	zone->start_addr = first_page_vaddr;
	zone->end_addr = zone->start_addr + page_num * BUDDY_PAGE_SIZE;

	/* init each free list (different orders) */
	for (i = 0; i < BUDDY_MAX_ORDER; i++) {
	        list = zone->free_lists + i;
		INIT_LIST_HEAD(&list->list_head);
		list->nr_free = 0;
	}

	/* zero the metadata area (struct relay_page for each relay_page) */
	memset((char*)first_page, 0, page_num * sizeof(struct relay_page));

	/* init the metadata for each relay_page */
	for (i = 0; i < page_num; i++) {
		/* Currently, 0~img_end is reserved, however, if we want to use them, we should reserve MP_BOOT_ADDR */
		relay_page = zone->first_page + i;
		INIT_LIST_HEAD(&relay_page->list_node);
		buddy_free_pages(zone, relay_page);
	}

	printk("mm: finish initing buddy memory system.\n");
}

struct relay_page *buddy_get_pages(struct global_mem *zone, u64 order)
{
	struct relay_page *relay_page;

	if (order >= BUDDY_MAX_ORDER) {
		printk("order: %lld, BUDDY_MAX_ORDER: %ld\n",
		       order, BUDDY_MAX_ORDER);
		BUG_ON(1);
		return NULL;
	}

	/* XXX Perf: maybe a dedicated lock for each list? */
	relay_page = __alloc_page(zone, order);

	return relay_page;
}

void buddy_free_pages(struct global_mem *zone, struct relay_page *relay_page)
{
	u64 order;
	struct relay_page *buddy;

	order = get_page_order(relay_page);

	/* clear head flag */
	relay_page->flags &= ~(1UL << RPG_head);

	/*
	 * order range: [0, BUDDY_MAX_ORDER).
	 * merge can only happens when order is less than
	 * (BUDDY_MAX_ORDER - 1)
	 */
	while (order < BUDDY_MAX_ORDER - 1) {
		/* find the corresponding (only-one) buddy (pages) to merge */
		buddy = get_buddy_page(zone, relay_page, order);

		/* check whether the buddy can be merged */
		if (!check_buddy(buddy, order))
			break;

		/* remove the buddy in its original free list */
		list_del(&buddy->list_node);
		zone->free_lists[order].nr_free--;
		/* clear the buddy's order and flag */
		clear_page_order_buddy(buddy);

		/* update relay_page after merged */
		relay_page = get_merge_page(zone, relay_page, order);
		order++;
	}

	/* set the merge one's order and flag */
	set_page_order_buddy(relay_page, order);
	list_add(&relay_page->list_node, &zone->free_lists[order].list_head);
	zone->free_lists[order].nr_free++;
}