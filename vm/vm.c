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
    frame_table_init();
    lock_init(&claim_lock);
    eviction_count = 0;
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

enum vm_type
page_get_union_type(struct page *page) {
    enum vm_type type = page_get_type(page);
    if(VM_TYPE (page->operations->type) != VM_UNINIT) {
        switch(type){
            case VM_ANON:
                type = page->anon.type;
                break;
            case VM_FILE:
                type = page->file.type;
                break;
            default:
                break;
        }
    }
    return type;
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
		/* Create the page, fetch the initialier according to the VM type,
		 * and then create "uninit" page struct by calling uninit_new. You
		 * should modify the field after calling the uninit_new. */
        struct page *new_page = calloc(sizeof(struct page), 1);
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
        new_page->pml4 = thread_current()->pml4;
        
        return spt_insert_page(spt, new_page);
	}
err:
	return false;
}

bool
vm_alloc_stack_page(void *upage) {
    return vm_alloc_page(VM_STACK | VM_ANON, upage, true);
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt, void *va) {
	struct page *result_page = NULL;
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

    succ = hash_insert(&spt->pages, &page->hash_elem) == NULL;

	return succ;
}

void
spt_remove_page (struct supplemental_page_table *spt UNUSED, struct page *page) {
	vm_dealloc_page (page);
}


struct frame *
ft_find_frame(void *kva) {
    struct frame *result_frame = NULL;
    struct hash_elem *e;
    struct frame f;

    f.kva = kva;
    e = hash_find(&frame_table, &f.hash_elem);
    if(e != NULL) {
        result_frame = hash_entry(e, struct frame, hash_elem);
    }

    return result_frame;
}


bool
ft_insert_frame(struct frame *frame) {
    int succ = false;
    succ = hash_insert(&frame_table, &frame->hash_elem) == NULL;
    return succ;
}


void
ft_remove_frame(struct frame *frame) {
    hash_delete(&frame_table, &frame->hash_elem);
}


void
frame_table_init(void) {
    hash_init(&frame_table, frame_hash, frame_less, NULL);
}


/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
    eviction_count++;

	struct frame *victim = NULL;
    struct hash_iterator ft_iter;
    struct frame *f;
    bool victim_is_dirty = true;
    bool done = false;

    hash_first (&ft_iter, &frame_table);
    while (hash_next (&ft_iter)) {
        f = hash_entry (hash_cur (&ft_iter), struct frame, hash_elem);

        if(f->page == NULL) {
            if(!done) {
                done = true;
                victim = f;
            }
            continue;
        }

        uint64_t *f_pml4 = f->page->pml4;
        if(!is_user_vaddr(f->page->va)) continue;
        if(pml4_get_page(f_pml4, f->page->va) == NULL) continue;
        if(pml4_is_accessed(f_pml4, f->page->va)) {
            pml4_set_accessed(f_pml4, f->page->va, false);
            if(done) continue;
            if(victim_is_dirty && !pml4_is_dirty(f_pml4, f->page->va)) {
                victim_is_dirty = false;
                victim = f;
            }
        } else {
            if(done) continue;
            victim_is_dirty = false;
            victim = f;
        }
        /* victim 후보의 우선순위
        우선순위 1: f->page != accessed  | timer 알고리즘. 가장 최근까지도 접근하지 않은 페이지가 할당되어있음
        우선순위 2: f->page != dirty     | swap out해주지 않아도 되는 페이지가 할당되어있음  */
    }

     /**
      * Frame table에서 매핑된 page와의 link를 끊을 frame을 찾아야 한다.
      * dirty한 page와 매핑된 frame을 꺼내게 되면
      * swap out을 해줘야 하므로,
      * 최대한 dirty 하지 않은 page와 매핑된 frame을 찾되,
      * 그런 frame이 없다면 dirty한 페이지-frame을 꺼내준다.
      * 
     */
    if(victim == NULL && f != NULL) {
        victim = f;
    }

	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim = vm_get_victim ();
    ASSERT(victim != NULL);

    if(victim->page != NULL) swap_out(victim->page);
    
	return victim;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame (void) {
	struct frame *frame = NULL;
    
    frame = malloc(sizeof(struct frame));
    frame->kva = palloc_get_page(PAL_USER);

    if(frame->kva == NULL) {
        free(frame);
        frame = vm_evict_frame();
    } else {
        ft_insert_frame(frame);
    }

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
        vm_alloc_stack_page(addr);
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
vm_try_handle_fault (struct intr_frame *f, void *addr, bool user UNUSED, bool write, bool not_present) {
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

    /**
     * supplemental page table에 존재하는 page의 주소(va ~ va + PGSIZE 사이)가
     * page fault를 발생시켰다면, 
     * 그 이유는 물리 메모리에 할당되지 못했기 때문이다.
     * 따라서 vm_do_claim_page()를 호출하여 해당 page를 물리 메모리에 할당시켜주는 방법으로
     * page fault를 해결한다.
    */
    page = spt_find_page(spt, addr);
    if(page == NULL) {
        return false;
    }

    lock_acquire(&claim_lock);
    bool success = vm_do_claim_page (page);
    lock_release(&claim_lock);
	return success;
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
    vm_initializer *init = NULL;
    struct page *dst;
    bool success = true;
    
    type = page_get_union_type(src);
    upage = src->va;
    writable = src->writable;

    // src의 operation에 따른 복사 대상 aux를 다르게 참조
    void *parent_eevee_aux = NULL;
    switch(VM_TYPE(src->operations->type)) {
        case VM_UNINIT:
            if(page_get_type(src) == VM_FILE) {
                return true;
            }
            parent_eevee_aux = src->uninit.aux;
            init = src->uninit.init;
            break;
        case VM_ANON:
            parent_eevee_aux = src->anon.aux;
            init = src->anon.init;
            break;
        case VM_FILE:
            return true;
            break;
        default:
            PANIC("page_duplicate() : unexpected type %d", type);
            break;
    }

    if(parent_eevee_aux != NULL) {
        struct lazy_args *parent_aux = (struct lazy_args *)parent_eevee_aux;
        struct lazy_args *child_aux = malloc(sizeof(struct lazy_args));

        if(child_aux == NULL) return false;

        child_aux->file = parent_aux->file;
        child_aux->file_ofs = parent_aux->file_ofs;
        child_aux->read_bytes = parent_aux->read_bytes;
        child_aux->zero_bytes = parent_aux->zero_bytes;
        aux = (void *)child_aux;
    }

    if(!vm_alloc_page_with_initializer(type, upage, writable, init, aux)) {
        return false;
    }

    dst = spt_find_page(spt, upage);
    if(dst == NULL) {
        return false;
    }

    if(VM_TYPE (src->operations->type) != VM_UNINIT) {
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
    lock_acquire(&claim_lock);
    hash_clear(&spt->pages, spt_destructor);
    lock_release(&claim_lock);
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


uint64_t 
frame_hash (const struct hash_elem *f_, void *aux UNUSED) {
    const struct frame *f = hash_entry (f_, struct frame, hash_elem);
    return hash_bytes (&f->kva, sizeof f->kva);
}

bool
frame_less (const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED) {
    const struct frame *a = hash_entry (a_, struct frame, hash_elem);
    const struct frame *b = hash_entry (b_, struct frame, hash_elem);
    return a->kva < b->kva;
}