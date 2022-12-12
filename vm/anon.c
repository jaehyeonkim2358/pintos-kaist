/* anon.c: Implementation of page for non-disk image (a.k.a. anonymous page). */

#include "vm/vm.h"
#include "devices/disk.h"
#include "threads/malloc.h"
#include "lib/string.h"
#include "threads/mmu.h"
#include <bitmap.h>

struct swap_table {
    struct lock lock;
    struct bitmap *used_slots;
};

struct swap_table swap_table;

size_t slot_cnt(void);

// used_slots의 비트 수
#define SLOT_CNT (slot_cnt())

// 한 슬롯당 섹터 수
#define SECTOR_PER_SLOT ((PGSIZE) / (DISK_SECTOR_SIZE))

// anon_page의 멤버 disk_sector_t의 초기값
#define SLOT_DEFAULTS (SLOT_CNT) + 1

// 섹터 번호를 슬롯 번호로 바꿔준다.
#define sector_to_slot(sec_no) ((disk_sector_t)((sec_no) / (SECTOR_PER_SLOT)))

// 슬롯 번호를 섹터 번호로 바꿔준다. disk와 관련된 함수 실행 시 사용한다.
#define slot_to_sector(slot_no) ((disk_sector_t)((slot_no) * (SECTOR_PER_SLOT)))

disk_sector_t salloc_get_multiple (size_t slot_cnt);
disk_sector_t salloc_get_slot(void);
void salloc_free_multiple(disk_sector_t slot_no, size_t slot_cnt);
void salloc_free_slot(disk_sector_t slot_no);
void write_to_swap_disk(disk_sector_t slot_no, void *upage);
void read_to_swap_disk(disk_sector_t slot_no, void *upage);

/* DO NOT MODIFY BELOW LINE */
static struct disk *swap_disk;
static bool anon_swap_in (struct page *page, void *kva);
static bool anon_swap_out (struct page *page);
static void anon_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations anon_ops = {
	.swap_in = anon_swap_in,
	.swap_out = anon_swap_out,
	.destroy = anon_destroy,
	.type = VM_ANON,
};

/* Initialize the data for anonymous pages */
void
vm_anon_init (void) {
	swap_disk = disk_get(1, 1);
    lock_init(&swap_table.lock);
    swap_table.used_slots = bitmap_create(SLOT_CNT);
}

/* Initialize the file mapping */
bool
anon_initializer (struct page *page, enum vm_type type, void *kva UNUSED) {
	/* Set up the handler */
	page->operations = &anon_ops;

	struct anon_page *anon_page = &page->anon;
    anon_page->init = page->uninit.init;
    anon_page->type = type;
    anon_page->aux = page->uninit.aux;
    anon_page->swap_slot_no = SLOT_DEFAULTS;

    return true;
}

/* swap_disk의 크기에 따른 가능한 슬롯의 최대갯수를 반환한다. */
size_t
slot_cnt(void) {
    return disk_size(swap_disk) / SECTOR_PER_SLOT;
}


/* 슬롯 할당기. SLOT_CNT개의 슬롯을 할당하고, 할당 받은 슬롯번호들 중 가장 작은 슬롯번호를 반환한다. */
disk_sector_t
salloc_get_multiple (size_t slot_cnt) {
    lock_acquire(&swap_table.lock);
    disk_sector_t slot_no = bitmap_scan_and_flip(swap_table.used_slots, 0, slot_cnt, false);
    lock_release(&swap_table.lock);

    return slot_no;
}


/* 하나의 슬롯을 할당한다. */
disk_sector_t
salloc_get_slot(void) {
    return salloc_get_multiple(1);
}


/* SLOT_NO부터 시작하는 SLOT_CNT개의 슬롯을 free 한다. */
void
salloc_free_multiple(disk_sector_t slot_no, size_t slot_cnt) {
    lock_acquire(&swap_table.lock);
    bitmap_set_multiple(swap_table.used_slots, slot_no, slot_cnt, false);
    lock_release(&swap_table.lock);
}


/* SLOT_NO 슬롯을 free한다. */
void
salloc_free_slot(disk_sector_t slot_no) {
    salloc_free_multiple(slot_no, 1);
}


void
write_to_swap_disk(disk_sector_t slot_no, void *upage) {
    disk_sector_t sec_no = slot_to_sector(slot_no);
    for(int i = 0; i < SECTOR_PER_SLOT; i++) {
        disk_write(swap_disk, sec_no + i, upage);
        upage += DISK_SECTOR_SIZE; 
    }
}


void
read_to_swap_disk(disk_sector_t slot_no, void *upage) {
    disk_sector_t sec_no = slot_to_sector(slot_no);
    for(int i = 0; i < SECTOR_PER_SLOT; i++) {
        disk_read(swap_disk, sec_no + i, upage);
        upage += DISK_SECTOR_SIZE;
    }
}


/* Swap in the page by read contents from the swap disk. 
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
 *    따라서 이런 페이지들은 "swap out 당한" 페이지들을 별도로 관리하는 테이블에서 관리되다가,
 *    swap in 요청시 그 테이블에서 제거되고,
 *    백업에 사용했던 디스크 영역의 내용을 다시 해당 페이지와 연결된 물리메모리에 옮겨 적어주어야 한다.
*/
static bool
anon_swap_in (struct page *page, void *kva) {
	struct anon_page *anon_page = &page->anon;
    disk_sector_t slot_no = anon_page->swap_slot_no;
    
    if(slot_no != SLOT_DEFAULTS) {
        read_to_swap_disk(slot_no, kva);
        salloc_free_slot(slot_no);
        anon_page->swap_slot_no = SLOT_DEFAULTS;
        return true;
    }
    return false;
}

/* Swap out the page by writing contents to the swap disk. 
 * anon 타입의 페이지는 디스크의 스왑 영역으로 백업된다.
 * 따라서 anon_swap_out()은
 * 인자로 받은 page의 가상 주소(va)와 매핑된 물리 주소(kva)에 저장되어있던 내용을
 * 디스크의 스왑 영역으로 옮겨 적어서 백업해야 한다.
 * 백업을 마치고 나면, 인자로 받은 page는 매핑되어있던 frame과의 link를 끊고,
 * 스왑 테이블로 들어가야 한다.
*/
static bool
anon_swap_out (struct page *page) {
	struct anon_page *anon_page = &page->anon;
    struct frame *frame = page->frame;
    disk_sector_t slot_no = salloc_get_slot();
    
    ASSERT(slot_no != BITMAP_ERROR);

    ASSERT(frame != NULL);

    // 할당 받은 slot_no를 저장하고 메모리의 내용을 swap disk에 백업
    anon_page->swap_slot_no = slot_no;
    write_to_swap_disk(slot_no, frame->kva);

    // 사용한 물리 메모리 영역 초기화
    memset(frame->kva, 0, PGSIZE);
    pml4_clear_page(page->pml4, page->va);

    // frame 연결관계 제거
    page->frame = NULL;

    return true;
}

/* Destroy the anonymous page. PAGE will be freed by the caller. */
static void
anon_destroy (struct page *page) {
	struct anon_page *anon_page = &page->anon;
    struct frame *frame = page->frame;
    void *anon_aux = anon_page->aux;
    disk_sector_t slot_no = anon_page->swap_slot_no;

    if(frame == NULL || anon_aux == NULL) {
        goto end;
    }

    memset(frame->kva, 0, PGSIZE);
    if(slot_no != SLOT_DEFAULTS) {
        write_to_swap_disk(slot_no, frame->kva);
        salloc_free_slot(slot_no);
    }
        
    // ! 왜 스택일때만 pml4_clear_page()를 해주어야 할까?
    if((anon_page->type & VM_STACK)) {
        pml4_clear_page(thread_current()->pml4, page->va);
        palloc_free_page(frame->kva);
    }

    ft_remove_frame(frame);
    page->frame = NULL;
    free(frame);
        
end:
    free(anon_aux);
}
