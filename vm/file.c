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
file_backed_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &file_ops;

	struct file_page *file_page = &page->file;
    file_page->type = type;
    file_page->aux = page->anon.aux;
    file_page->mapping_address = page->mapping_address;
    
    return true;
}

/* Swap in the page by read contents from the file. */
static bool
file_backed_swap_in (struct page *page, void *kva) {
	struct file_page *file_page UNUSED = &page->file;
}

/* Swap out the page by writeback contents to the file. */
static bool
file_backed_swap_out (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void
file_backed_destroy (struct page *page) {
	struct file_page *file_page = &page->file;
    void *file_eevee_aux;

    if(page->frame != NULL) {
        if(file_page->aux != NULL) {
            struct lazy_args *file_aux = (struct lazy_args *)file_page->aux;
            if(pml4_is_dirty(thread_current()->pml4, page->va)) {
                struct file *mapped_file = file_aux->file;
                off_t mapped_offset = file_aux->file_ofs;
                size_t mapped_read_bytes = file_aux->read_bytes;
                bool file_lock_holder = lock_held_by_current_thread(&file_lock);
                
                if(!file_lock_holder) lock_acquire(&file_lock);
                file_seek(mapped_file, mapped_offset);
                file_write(mapped_file, page->frame->kva, mapped_read_bytes);
                file_close(mapped_file);
                if(!file_lock_holder) lock_release(&file_lock);
            }
            free(file_aux);
        }
        free(page->frame);
    }
}

/* Do the mmap */
void *
do_mmap (void *addr, size_t length, int writable, struct file *file, off_t offset) {
    size_t read_length, zero_length;

    read_length = length < file_length(file) ? length : file_length(file);
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

    while(target != NULL && target->file.mapping_address == addr) {
        hash_delete(&spt->pages, &target->hash_elem);
        vm_dealloc_page(target);
        buffer += PGSIZE;
        target = spt_find_page(spt, buffer);
    }
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

	while (read_bytes > 0 || zero_bytes > 0) {
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

        struct lazy_args *la = malloc(sizeof(struct lazy_args));
        *la = (struct lazy_args) {
            .file = file_reopen(file),
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

        file_offset += page_read_bytes;
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}