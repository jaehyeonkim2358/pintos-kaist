/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "threads/mmu.h"
#include "vm/inspect.h"
#include "threads/synch.h"
#include "lib/string.h"
#include "userprog/process.h"
#include "userprog/syscall.h"

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void
vm_init (void) {
	vm_anon_init ();
	vm_file_init ();
#ifdef EFILESYS  /* For project 4 */
	pagecache_init ();
#endif
	register_inspect_intr ();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type (struct page *page) {
	int ty = VM_TYPE (page->operations->type);
	switch (ty) {
		case VM_UNINIT:
			return VM_TYPE (page->uninit.type);
		default:
			return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim (void);
static bool vm_do_claim_page (struct page *page);
static struct frame *vm_evict_frame (void);
bool page_duplicate(struct supplemental_page_table *spt, struct page *src);
void spt_destructor(struct hash_elem *e, void *aux);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`.
 * 
 * inintializer와 함께 페이지를 만드세요.
 * page 생성은 직접 하지 말고 이 함수나 'vm_alloc_page'을 이용하세요!
 *  */
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable, vm_initializer *init, void *aux) {
	ASSERT (VM_TYPE(type) != VM_UNINIT)

	struct supplemental_page_table *spt = &thread_current ()->spt;
    
	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) {
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */
        struct page *new_page = malloc(sizeof(struct page));
        bool (*initializer)(struct page *, enum vm_type, void *kva);

        if(new_page == NULL) {
            goto err;
        }
        
        switch(VM_TYPE(type)){
            case VM_ANON:
                initializer = anon_initializer;
                break;
            case VM_FILE:
                initializer = file_backed_initializer;
                break;
            default:
                PANIC("vm_alloc_page_with_initializer() : unexpected type %d", type);
                break;
        }
        
        uninit_new(new_page, upage, init, type, aux, initializer);
        new_page->writable = writable;
        
        return spt_insert_page(spt, new_page);
	}
err:
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt, void *va) {
	struct page *result_page = NULL;
	/* TODO: Fill this function. */
    struct hash_elem *e;
    struct page p;

    p.va = pg_round_down(va);
    e = hash_find(&spt->pages, &p.hash_elem);
    if(e != NULL) {
        result_page = hash_entry(e, struct page, hash_elem);
    }

    return result_page;
}

/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt, struct page *page) {
	int succ = false;
	/* TODO: Fill this function. */
    succ = hash_insert(&spt->pages, &page->hash_elem) == NULL;

	return succ;
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	vm_dealloc_page (page);
	return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
	struct frame *victim = NULL;
	 /* TODO: The policy for eviction is up to you. */

	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim UNUSED = vm_get_victim ();
	/* TODO: swap out the victim and return the evicted frame. */

	return NULL;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame (void) {
	struct frame *frame = NULL;
	/* TODO: Fill this function. */
    frame = malloc(sizeof(struct frame));
    frame->kva = palloc_get_page(PAL_USER);
    frame->page = NULL;

	ASSERT (frame != NULL);
	ASSERT (frame->page == NULL);

	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr) {
    struct supplemental_page_table *spt = &thread_current()->spt;
    addr = pg_round_down(addr);
    while(spt_find_page(spt, addr) == NULL) {
        vm_alloc_page(VM_ANON | VM_STACK, addr, true);
        vm_claim_page(addr);
        addr += PGSIZE;
    }
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

/* Return true on success */
bool
vm_try_handle_fault (struct intr_frame *f, void *addr, bool user, bool write, bool not_present) {
	struct supplemental_page_table *spt = &thread_current ()->spt;
	struct page *page = NULL;

    /* physical page는 존재하나, 
       writable하지 않은 address에 write를 시도해서 일어난 fault인 경우, 
       할당하지 않고 즉시 false를 반환한다. */
    if((!not_present) && (write)) {
        return false;
    }

    /* fault를 발생시킨 address가 Stack영역 주소 범위내의 주소임과 동시에,
       rsp - 8 (return address 저장 후의 주소) 보다 주소값이 큰 경우
       (Stack bottom ~ rsp 사이의 주소인 경우), Stack 영역을 신장시킨다.
       address가 Stack영역의 범위내에 있지만 rsp보다 주소값이 작을 경우
       (Stack bottom에서 부터의 길이가 rsp보다 멀리있는 영역의 주소인 경우),
       잘못된 접근 이므로 즉시 false를 반환한다. */
    if(USER_STACK_END < addr && addr <= USER_STACK) {
        if(f->rsp - 8 <= addr) {
            vm_stack_growth(addr);
            return true;
        } else {
            return false;
        }
    }

    page = spt_find_page(spt, addr);
    if(page == NULL) {
        return false;
    }

	return vm_do_claim_page (page);
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}

/* Claim the page that allocate on VA. */
bool
vm_claim_page (void *va) {
	struct page *page = NULL;
    struct supplemental_page_table *spt = &thread_current()->spt;
	/* TODO: Fill this function */
    page = spt_find_page(spt, va);
    if(page == NULL) {
        return false;
    }

	return vm_do_claim_page (page);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page (struct page *page) {
	struct frame *frame = vm_get_frame ();

	/* Set links */
	frame->page = page;
	page->frame = frame;

	/* TODO: Insert page table entry to map page's VA to frame's PA. */
    if(!pml4_set_page(thread_current()->pml4, page->va, frame->kva, page->writable)) {
        return false;
    }
    
	return swap_in (page, frame->kva);
}

/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt) {
    hash_init(&spt->pages, page_hash, page_less, NULL);
}

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst,
		struct supplemental_page_table *src) {
    struct hash *dst_hash = &dst->pages;
    struct hash *src_hash = &src->pages;
    struct hash_iterator src_iter;

    hash_first(&src_iter, src_hash);
    while (hash_next (&src_iter)) {
        struct page *src_page = hash_entry (hash_cur (&src_iter), struct page, hash_elem);
        if(!page_duplicate(dst, src_page)) {
            return false;
        }
    }
    return true;
}

bool
page_duplicate(struct supplemental_page_table *spt, struct page *src) {
    enum vm_type type;
    void *upage, *aux = NULL;
    bool writable;
    vm_initializer *init;
    struct page *dst;
    bool success = true;
    
    type = page_get_type(src);
    upage = src->va;
    writable = src->writable;
    init = src->uninit.init;

    // src 페이지에 aux가 존재할 경우 할당
    if(src->uninit.aux != NULL) {
        struct lazy_args *old_aux = (struct lazy_args *)src->uninit.aux;
        struct lazy_args *new_aux = malloc(sizeof(struct lazy_args));

        if(new_aux == NULL) return false;

        new_aux->file = old_aux->file;
        new_aux->file_ofs = old_aux->file_ofs;
        new_aux->read_bytes = old_aux->read_bytes;
        new_aux->zero_bytes = old_aux->zero_bytes;
        aux = (void *)new_aux;
    }

    if(!vm_alloc_page_with_initializer(type, upage, writable, init, aux)) {
        return false;
    }

    dst = spt_find_page(spt, upage);
    if(dst == NULL) {
        return false;
    }

    if(src->frame != NULL) {
        success = vm_do_claim_page(dst);
        if(success) {
            memcpy(dst->frame->kva, src->frame->kva, PGSIZE);
        }
    }
    
    return success;
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and */
	/* TODO: writeback all the modified contents to the storage. */
    hash_clear(&spt->pages, spt_destructor);
}

void
spt_destructor(struct hash_elem *e, void *aux UNUSED) {
    struct page *target = hash_entry (e, struct page, hash_elem);

    vm_dealloc_page(target);
}


uint64_t 
page_hash (const struct hash_elem *p_, void *aux UNUSED) {
    const struct page *p = hash_entry (p_, struct page, hash_elem);
    return hash_bytes (&p->va, sizeof p->va);
}

bool
page_less (const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED) {
    const struct page *a = hash_entry (a_, struct page, hash_elem);
    const struct page *b = hash_entry (b_, struct page, hash_elem);
    return a->va < b->va;
}