/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"
#include "threads/vaddr.h"
#include "lib/string.h"
#include "lib/round.h"
#include "threads/malloc.h"
#include "userprog/process.h"
#include "userprog/syscall.h"
#include "threads/mmu.h"

static bool file_backed_swap_in (struct page *page, void *kva);
static bool file_backed_swap_out (struct page *page);
static void file_backed_destroy (struct page *page);
static bool file_load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable);
static bool file_lazy_load_segment (struct page *page, void *aux);
void file_backed_write_back(void *aux, void *kva);

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
	.swap_in = file_backed_swap_in,
	.swap_out = file_backed_swap_out,
	.destroy = file_backed_destroy,
	.type = VM_FILE,
};

/* The initializer of file vm */
void
vm_file_init (void) {
}

/* Initialize the file backed page */
bool
file_backed_initializer (struct page *page, enum vm_type type, void *kva UNUSED) {
	/* Set up the handler */
	page->operations = &file_ops;

	struct file_page *file_page = &page->file;
    file_page->init = page->uninit.init;
    file_page->type = type;
    file_page->aux = page->uninit.aux;
    file_page->mapping_address = page->mapping_address;
    file_page->file_holder_cnt = page->file_holder_cnt;
    
    return true;
}

/* Swap in the page by read contents from the file.
 * swap_in()이 호출되는 시점은 vm_claim_page()또는 vm_do_claim_page()를 호출하는 시점이고,
 * 위의 두 claim 함수를 호출하는 시점은
 *   - vm_try_handle_fault()
 *   - supplemental_page_table_copy()
 * 2가지 함수가 호출되었을 때 이다.
 * 
 * swap in되는 2가지 경우가 존재한다.
 * 
 * 1. uninit 타입 페이지의 경우에는 아직 물리메모리에 매핑되었던 적이 없던 페이지이므로,
 *    처음으로 frame을 할당받을것이며, 이는 백업된 내용이 없다는 뜻이고,
 *    따라서 "물리 메모리에 다시 써줄 내용" 이 존재하지 않기 때문에, 
 *    uninit_initialize() 라는 함수를 operation의 swap_in멤버로 사용했다.
 * 
 * 2. uninit 타입이 아닌 페이지의 경우 한번 물리메모리에 매핑되었던 적이 있었다는 의미이며,
 *    이런 페이지에 대해 swap in 요청이 들어왔다는 것은
 *    해당 페이지가 물리메모리에 한번 이상 매핑된 뒤, swap out된 적이 있다는 의미이다.
 *    따라서 이런 페이지들은 
 *    백업에 사용했던 디스크 영역의 내용을 다시 해당 페이지와 연결된 물리메모리에 옮겨 적어주어야 한다.
*/
static bool
file_backed_swap_in (struct page *page, void *kva) {
	struct file_page *file_page = &page->file;
    void *file_eevee_aux = file_page->aux;
    
    if(file_eevee_aux != NULL) {
        struct lazy_args *file_aux = (struct lazy_args *)file_eevee_aux;
        struct file *mapped_file = file_aux->file;
        off_t mapped_offset = file_aux->file_ofs;
        size_t mapped_read_bytes = file_aux->read_bytes;
        size_t mapped_zero_bytes = file_aux->zero_bytes;
        bool file_lock_holder = lock_held_by_current_thread(&file_lock);

        if(!file_lock_holder) lock_acquire(&file_lock);
        file_seek(mapped_file, mapped_offset);
        if(file_read(mapped_file, kva, mapped_read_bytes) != (int)mapped_read_bytes) {
            return false;
        }
        if(!file_lock_holder) lock_release(&file_lock);

        memset (kva + mapped_read_bytes, 0, mapped_zero_bytes);
    }
    return true;
}

/* Swap out the page by writeback contents to the file.
 * file 타입의 페이지는, Dirty하다면, 원래 파일이 있던 디스크의 영역으로 백업된다.
 * 따라서 file_backed_swap_out()은 해당 페이지가 Dirty할 때 호출되며,
 * 인자로 받은 page의 가상 주소(va)와 매핑된 물리 주소(kva)에 저장되어있던 내용을
 * 파일에 옮겨 적어서 백업해야 한다.
 * 백업을 마치고 나면, 인자로 받은 page는 매핑되어있던 frame과의 link를 끊어야 한다.
*/
static bool
file_backed_swap_out (struct page *page) {
	struct file_page *file_page = &page->file;
    struct frame *frame = page->frame;
    void *file_eevee_aux = file_page->aux;

    if(frame == NULL || file_eevee_aux == NULL) {
        goto end;
    }

    if(pml4_is_dirty(page->pml4, page->va)) {
        file_backed_write_back(file_eevee_aux, frame->kva);
        pml4_set_dirty(page->pml4, page->va, false);
    }

    if(pml4_get_page(page->pml4, page->va) != NULL) {
        memset(frame->kva, 0, PGSIZE);
        pml4_clear_page(page->pml4, page->va);
    }

    page->frame = NULL;

end:
    return true;
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void
file_backed_destroy (struct page *page) {
	struct file_page *file_page = &page->file;
    struct frame *frame = page->frame;
    void *file_eevee_aux = file_page->aux;

    if(frame == NULL || file_eevee_aux == NULL) {
        goto end;
    }

    struct lazy_args *file_aux = (struct lazy_args *)file_eevee_aux;
    bool file_lock_holder = lock_held_by_current_thread(&file_lock);

    if(pml4_is_dirty(thread_current()->pml4, page->va)) {
        file_backed_write_back(file_eevee_aux, frame->kva);
    }

    if(--(file_page->file_holder_cnt) == 0) {
        if(!file_lock_holder) lock_acquire(&file_lock);
        file_close(file_aux->file);
        free(file_page->file_holder_cnt);
        if(!file_lock_holder) lock_release(&file_lock);
    }
    
    // 사용한 물리 메모리 영역 초기화 및 페이지 테이블에서 user virtual address 매핑 해제
    memset(frame->kva, 0, PGSIZE);
    pml4_clear_page(thread_current()->pml4, page->va);

    // frame의 연결관계 제거
    ft_remove_frame(frame);
    page->frame = NULL;

    // frame 구조체를 위해 할당된 메모리 해제
    palloc_free_page(frame->kva);
    free(frame);

end:
    free(file_eevee_aux);
}


void
file_backed_write_back(void *aux, void *kva) {
    ASSERT(aux != NULL);

    struct lazy_args *file_aux = (struct lazy_args *)aux;
    struct file *mapped_file = file_aux->file;
    bool file_lock_holder = lock_held_by_current_thread(&file_lock);

    off_t mapped_offset = file_aux->file_ofs;
    size_t mapped_read_bytes = file_aux->read_bytes;
    
    if(!file_lock_holder) lock_acquire(&file_lock);
    file_seek(mapped_file, mapped_offset);
    file_write(mapped_file, kva, mapped_read_bytes);
    if(!file_lock_holder) lock_release(&file_lock);
}


/* Do the mmap */
void *
do_mmap (void *addr, size_t length, int writable, struct file *file, off_t offset) {
    size_t read_length, zero_length;

    file = file_reopen(file);
    read_length = length < (size_t)file_length(file) ? length : (size_t)file_length(file);
    zero_length = (read_length % PGSIZE == 0) ? 0 : PGSIZE - (read_length % PGSIZE);
    
    if(!file_load_segment(file, offset, addr, read_length, zero_length, writable)) {
        return NULL;
    }

    return addr;
}

/* Do the munmap */
void
do_munmap (void *addr) {
    struct supplemental_page_table *spt = &thread_current()->spt;
    struct page *target;
    void *buffer = addr;

    target = spt_find_page(spt, addr);
    if(target == NULL
        || page_get_type(target) != VM_FILE
        || target->file.mapping_address != addr) {
        PANIC("do_munmap() : unexpected address %p", addr);
    }

    lock_acquire(&claim_lock);
    while(target != NULL && target->file.mapping_address == addr) {
        hash_delete(&spt->pages, &target->hash_elem);
        vm_dealloc_page(target);
        buffer += PGSIZE;
        target = spt_find_page(spt, buffer);
    }
    lock_release(&claim_lock);
}


static bool 
file_lazy_load_segment (struct page *page, void *aux) {
    struct lazy_args *args = (struct lazy_args *)aux;
    struct file *file = args->file;
    off_t ofs = args->file_ofs;
    size_t read_bytes = args->read_bytes;
    size_t zero_bytes = args->zero_bytes;
    bool file_lock_holder = lock_held_by_current_thread(&file_lock);

    if(!file_lock_holder) lock_acquire(&file_lock);
    file_seek(file, ofs);
    if (file_read (file, page->frame->kva, read_bytes) != (int) read_bytes) {
        return false;
    }
    if(!file_lock_holder) lock_release(&file_lock);

    memset (page->frame->kva + read_bytes, 0, zero_bytes);
    
    return true;
}


static bool
file_load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

    size_t file_offset = ofs;
    uint8_t *mapping_address = upage;
    unsigned *file_holder_cnt = (unsigned *)malloc(sizeof(unsigned));
    *file_holder_cnt = (read_bytes + zero_bytes) / PGSIZE;

	while (read_bytes > 0 || zero_bytes > 0) {
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

        struct lazy_args *la = malloc(sizeof(struct lazy_args));
        *la = (struct lazy_args) {
            .file = file,
            .file_ofs = file_offset,
            .read_bytes = page_read_bytes,
            .zero_bytes = page_zero_bytes
        };
		void *aux = (void *)la;
        
		if (!vm_alloc_page_with_initializer (VM_FILE, upage, writable, file_lazy_load_segment, aux)) {
            return false;
        }
        struct page *p = spt_find_page(&thread_current()->spt, upage);
        p->mapping_address = mapping_address;
        p->file_holder_cnt = file_holder_cnt;

        file_offset += page_read_bytes;
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}