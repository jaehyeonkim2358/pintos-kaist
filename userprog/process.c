#include "userprog/process.h"
#include "userprog/syscall.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/mmu.h"
#include "threads/vaddr.h"
#include "threads/malloc.h" // malloc() 쓸거야
#include "intrinsic.h"
#include "lib/string.h"
#include "lib/stdio.h"      // hex_dump() 쓸거야

#ifdef VM
#include "vm/vm.h"
#endif


struct parent_proc {
    struct thread *parent;
    struct intr_frame *user_frame;
    struct semaphore sema;
};


static void process_cleanup (void);
static bool load (const char *file_name, struct intr_frame *if_);
static void initd (void *f_name);
static void __do_fork (void **);


struct child_list_elem * process_set_child_list(struct thread *parent, struct thread *child);


/* General process initializer for initd and other process. */
static void
process_init (void) {
	struct thread *current = thread_current ();
}

/* Starts the first userland program, called "initd", loaded from FILE_NAME.
 * The new thread may be scheduled (and may even exit)
 * before process_create_initd() returns. Returns the initd's
 * thread id, or TID_ERROR if the thread cannot be created.
 * Notice that THIS SHOULD BE CALLED ONCE. */
tid_t
process_create_initd (const char *file_name) {
	char *fn_copy;
	tid_t tid;

	/* Make a copy of FILE_NAME.
	 * Otherwise there's a race between the caller and load(). */
	fn_copy = palloc_get_page (0);
	if (fn_copy == NULL)
		return TID_ERROR;
	strlcpy (fn_copy, file_name, PGSIZE);
    char *tmp;
    file_name = strtok_r(file_name, " ", &tmp);

	/* Create a new thread to execute FILE_NAME. */
	tid = thread_create (file_name, PRI_DEFAULT, initd, fn_copy);
	if (tid == TID_ERROR) {
        palloc_free_page (fn_copy);
    }
	return tid;
}

/* A thread function that launches first user process. */
static void
initd (void *f_name) {
#ifdef VM
	supplemental_page_table_init (&thread_current ()->spt);
#endif

	process_init ();
	if (process_exec (f_name) < 0) {
        PANIC("Fail to launch initd\n");
    }
	NOT_REACHED ();
}

/* Clones the current process as `name`. Returns the new process's thread id, or
 * TID_ERROR if the thread cannot be created. */
tid_t
process_fork (const char *name, struct intr_frame *if_) {
    struct semaphore sema;
    struct thread *p_thread = thread_current();
    void *arr[3] = {p_thread, if_, &sema};
    tid_t child_pid = 0;
    
    sema_init(&sema, 0);

    /* Clone current thread to new thread.*/
    child_pid = thread_create (name, PRI_DEFAULT, __do_fork, arr);

    if(child_pid == TID_ERROR) {
        return TID_ERROR;
    } else {
        sema_down(&sema);
        if(get_child_exit_status(thread_current(), child_pid) == -1) {
            return -1;
        }
    }
    
	return child_pid;
}


int
get_child_exit_status (struct thread* parent, tid_t child_tid) {
    struct list *child_list = &parent->child_list;
    struct list_elem *cur;
    struct child_list_elem *target = NULL;

    if(!list_empty(child_list)) {
        cur = list_begin(child_list);

        /* child_list에서 tid가 child_tid랑 같은 자식을 찾는다. */
        while(cur != list_tail(child_list)) {
            target = list_entry(cur, struct child_list_elem, elem);

            if(target->child_tid == child_tid) {
                return target->child_exit_status;
            }
            cur = list_next(cur);
        }
    }
    return -1;
}


#ifndef VM
/* Duplicate the parent's address space by passing this function to the
 * pml4_for_each. This is only for the project 2. */
static bool
duplicate_pte (uint64_t *pte, void *va, void *aux) {
	struct thread *current = thread_current ();
	struct thread *parent = (struct thread *) aux;
	void *parent_page;
	void *newpage;
	bool writable;

	/* 1. TODO: If the parent_page is kernel page, then return immediately. */
    if(is_kern_pte(pte)) return true;
    

	/* 2. Resolve VA from the parent's page map level 4. */
	parent_page = pml4_get_page (parent->pml4, va);

	/* 3. TODO: Allocate new PAL_USER page for the child and set result to
	 *    TODO: NEWPAGE. */
    newpage = palloc_get_page(PAL_USER);        // PAL_USER

	/* 4. TODO: Duplicate parent's page to the new page and
	 *    TODO: check whether parent's page is writable or not (set WRITABLE
	 *    TODO: according to the result). */
    memcpy(newpage, parent_page, PGSIZE);
    writable = is_writable(pte);

	/* 5. Add new page to child's page table at address VA with WRITABLE
	 *    permission. */
	if (!pml4_set_page (current->pml4, va, newpage, writable)) {
        // PANIC("fail to insert page");
		/* 6. TODO: if fail to insert page, do error handling. */
        palloc_free_page(newpage);
        return false;
	}
	return true;
}
#endif

/* A thread function that copies parent's execution context.
 * Hint) parent->tf does not hold the userland context of the process.
 *       That is, you are required to pass second argument of process_fork to
 *       this function. */
static void
__do_fork (void **aux) {
	struct intr_frame if_;
	struct thread *parent = (struct thread *)aux[0];
	struct thread *current = thread_current ();
	struct intr_frame *parent_if = (struct intr_frame *)aux[1];         /* Project2: System Calls */
    struct semaphore *sema = (struct semaphore *)aux[2];
	bool succ = true;

	/* 1. Read the cpu context to local stack. */
	memcpy (&if_, parent_if, sizeof (struct intr_frame));

	/* 2. Duplicate PT */
	current->pml4 = pml4_create();
	if (current->pml4 == NULL) {
		goto error;
    }

	process_activate (current);
#ifdef VM
	supplemental_page_table_init (&current->spt);
	if (!supplemental_page_table_copy (&current->spt, &parent->spt))
		goto error;
#else
	if (!pml4_for_each (parent->pml4, duplicate_pte, parent)) {
		goto error;
    }
#endif

	/* TODO: Your code goes here.
	 * TODO: Hint) To duplicate the file object, use `file_duplicate`
	 * TODO:       in include/filesys/file.h. Note that parent should not return
	 * TODO:       from the fork() until this function successfully duplicates
	 * TODO:       the resources of parent.*/
    /* Project2: System Calls */
    if(parent->my_exec_file != NULL) {
        lock_acquire(&file_lock);
        current->my_exec_file = file_duplicate(parent->my_exec_file);
        lock_release(&file_lock);
    }
    
    for(int i = 0; i < FDLIST_LEN; i++) {
        struct file *p_f = (parent->fd_table)[i];
        if(p_f == NULL) continue;

        struct file *dup_f;
        lock_acquire(&file_lock);
        dup_f = file_duplicate(p_f);
        lock_release(&file_lock);
        if(dup_f == NULL) {
            goto error;
        }
        (current->fd_table)[i] = dup_f;
    }
    
    process_init();
    
	/* Finally, switch to the newly created process. */
    if_.R.rax = 0;
    sema_up(sema);

	if (succ) {
        do_iret (&if_);
    }
error:
    current->my_info->child_exit_status = -1;
    sema_up(sema);
    current->exit_status = -1;
	thread_exit ();
}

struct child_list_elem *
process_set_child_list(struct thread *parent, struct thread *child) {
    struct child_list_elem *child_elem = malloc(sizeof(struct child_list_elem));
    child_elem->child_status = child->status;
    child_elem->child_tid = child->tid;
    child_elem->child_exit_status = 0;
    child_elem->child = child;
    sema_init(&child_elem->wait_sema, 0);
    
    list_push_back(&parent->child_list, &child_elem->elem);
    return child_elem;
}


/* Switch the current execution context to the f_name.
 * Returns -1 on fail. */
int
process_exec (void *f_name) {
	char *file_name = f_name;
	bool success;

	/* We cannot use the intr_frame in the thread structure.
	 * This is because when current thread rescheduled,
	 * it stores the execution information to the member. */
	struct intr_frame _if;
	_if.ds = _if.es = _if.ss = SEL_UDSEG;
	_if.cs = SEL_UCSEG;
	_if.eflags = FLAG_IF | FLAG_MBS;

	/* We first kill the current context */
	process_cleanup ();

	/* And then load the binary */
	success = load (file_name, &_if);

	/* If load failed, quit. */
	palloc_free_page (file_name);
	if (!success) {
		return -1;
    }

	/* Start switched process. */
	do_iret (&_if);
	NOT_REACHED ();
}




/* Waits for thread TID to die and returns its exit status.  If
 * it was terminated by the kernel (i.e. killed due to an
 * exception), returns -1.  If TID is invalid or if it was not a
 * child of the calling process, or if process_wait() has already
 * been successfully called for the given TID, returns -1
 * immediately, without waiting.
 *
 * This function will be implemented in problem 2-2.  For now, it
 * does nothing. */
int
process_wait (tid_t child_tid) {
    struct thread *current = thread_current();
    int return_val = 0;

    struct list *child_list = &current->child_list;
    struct list_elem *cur;
    struct child_list_elem *target;

    if(!list_empty(child_list)) {
        cur = list_begin(child_list);
        target = NULL;

        /* child_list에서 tid가 child_tid랑 같은 자식을 찾는다. */
        while(cur != list_tail(child_list)) {
            target = list_entry(cur, struct child_list_elem, elem);

            /* 자식을 찾은 뒤, 필요한 정보를 꺼내고, child_list에서 제거하고, child_list_elem을 free한다. */
            if(target->child_tid == child_tid) {
                while(target->child_status != THREAD_DYING) {
                    sema_down(&target->wait_sema);
                }
                return_val = target->child_exit_status;
                list_remove(cur);
                free(target);
                return return_val;
            }
            cur = list_next(cur);
        }
    }
    return -1;
}

/* Exit the process. This function is called by thread_exit (). */
void
process_exit (void) {
	struct thread *curr = thread_current ();
    struct thread *parent = curr->parent_process;
    int curr_exit_status = curr->exit_status;

    if(curr->pml4 != NULL) {
        printf("%s: exit(%d)\n",curr->name, curr_exit_status);
    }

    process_cleanup ();

    /* 실행하던 파일 닫기 */
    if(curr->my_exec_file != NULL) {
        lock_acquire(&file_lock);
        file_close(curr->my_exec_file);
        lock_release(&file_lock);
        curr->my_exec_file = NULL;
    }

    /* fd table의 파일 닫기 */
    lock_acquire(&file_lock);
    for(int i = 0; i < FDLIST_LEN; i++) {
        file_close(curr->fd_table[i]);
    }
    lock_release(&file_lock);

    /* child_list의 child_list_elem들을 free() 한다. */
    enum intr_level old_level;
    old_level = intr_disable();
    while(!list_empty(&curr->child_list)) {
        struct child_list_elem *tgt = list_entry(list_pop_front(&curr->child_list), struct child_list_elem, elem);
        /* 아직 살아있는 자식이라면, free() 전에 해당 멤버를 NULL로 바꿔준다. */
        if(tgt->child_status != THREAD_DYING) {
            tgt->child->my_info = NULL;
        }
        free(tgt);
    }
    intr_set_level(old_level);

    /* 부모 process가 살아있다면, 사망 여부를 알려준다. */
    if(curr->my_info != NULL) {
        curr->my_info->child_status = THREAD_DYING;
        curr->my_info->child_exit_status = curr_exit_status;
        sema_up(&curr->my_info->wait_sema);
    }
}

/* Free the current process's resources. */
static void
process_cleanup (void) {
	struct thread *curr = thread_current ();

#ifdef VM
	supplemental_page_table_kill (&curr->spt);
#endif

	uint64_t *pml4;
	/* Destroy the current process's page directory and switch back
	 * to the kernel-only page directory. */
	pml4 = curr->pml4;
	if (pml4 != NULL) {
		/* Correct ordering here is crucial.  We must set
		 * cur->pagedir to NULL before switching page directories,
		 * so that a timer interrupt can't switch back to the
		 * process page directory.  We must activate the base page
		 * directory before destroying the process's page
		 * directory, or our active page directory will be one
		 * that's been freed (and cleared). */
		curr->pml4 = NULL;
		pml4_activate (NULL);
		pml4_destroy (pml4);
	}
}

/* Sets up the CPU for running user code in the nest thread.
 * This function is called on every context switch. */
void
process_activate (struct thread *next) {
	/* Activate thread's page tables. */
	pml4_activate (next->pml4);

	/* Set thread's kernel stack for use in processing interrupts. */
	tss_update (next);
}

/* We load ELF binaries.  The following definitions are taken
 * from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
#define EI_NIDENT 16

#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
 * This appears at the very beginning of an ELF binary. */
struct ELF64_hdr {
	unsigned char e_ident[EI_NIDENT];
	uint16_t e_type;
	uint16_t e_machine;
	uint32_t e_version;
	uint64_t e_entry;
	uint64_t e_phoff;
	uint64_t e_shoff;
	uint32_t e_flags;
	uint16_t e_ehsize;
	uint16_t e_phentsize;
	uint16_t e_phnum;
	uint16_t e_shentsize;
	uint16_t e_shnum;
	uint16_t e_shstrndx;
};

struct ELF64_PHDR {
	uint32_t p_type;
	uint32_t p_flags;
	uint64_t p_offset;
	uint64_t p_vaddr;
	uint64_t p_paddr;
	uint64_t p_filesz;
	uint64_t p_memsz;
	uint64_t p_align;
};

/* Abbreviations */
#define ELF ELF64_hdr
#define Phdr ELF64_PHDR

static bool setup_stack (struct intr_frame *if_);
static bool validate_segment (const struct Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes,
		bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
 * Stores the executable's entry point into *RIP
 * and its initial stack pointer into *RSP.
 * Returns true if successful, false otherwise. */
static bool
load (const char *file_name, struct intr_frame *if_) {
	struct thread *t = thread_current ();
	struct ELF ehdr;
	struct file *file = NULL;
	off_t file_ofs;
	bool success = false;
	int i;

    if(t->my_exec_file != NULL) {
        lock_acquire(&file_lock);
        file_close(t->my_exec_file);
        lock_release(&file_lock);
        t->my_exec_file = NULL;
    }

	/* Allocate and activate page directory. */
	t->pml4 = pml4_create ();
	if (t->pml4 == NULL) {
		goto done;
    }
	process_activate (thread_current ());

    /* PROJECT 2: ARGUMENT PASSING */
    char *save_ptr, *f_name;
    char *tmp, *args[40];
    int argc = 1;

    args[0] = strtok_r(file_name, " ", &save_ptr);
    while((tmp = strtok_r(NULL, " ", &save_ptr)) != NULL) {
        args[argc] = tmp;
        argc++;
    }

	/* Open executable file. */
    lock_acquire(&file_lock);
	file = filesys_open (file_name);
    lock_release(&file_lock);
	if (file == NULL) {
		printf ("load: %s: open failed\n", file_name);
		goto done;
	}

	/* Read and verify executable header. */
    lock_acquire(&file_lock);
	if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
			|| memcmp (ehdr.e_ident, "\177ELF\2\1\1", 7)
			|| ehdr.e_type != 2
			|| ehdr.e_machine != 0x3E // amd64
			|| ehdr.e_version != 1
			|| ehdr.e_phentsize != sizeof (struct Phdr)
			|| ehdr.e_phnum > 1024) {
        lock_release(&file_lock);
		printf ("load: %s: error loading executable\n", file_name);
		goto done;
	}
    lock_release(&file_lock);

	/* Read program headers. */
	file_ofs = ehdr.e_phoff;
	for (i = 0; i < ehdr.e_phnum; i++) {
		struct Phdr phdr;
        lock_acquire(&file_lock);
		if (file_ofs < 0 || file_ofs > file_length (file)) {
            lock_release(&file_lock);
            goto done;
        }
        lock_release(&file_lock);

		lock_acquire(&file_lock);
		file_seek (file, file_ofs);
        lock_release(&file_lock);

        lock_acquire(&file_lock);
		if (file_read (file, &phdr, sizeof phdr) != sizeof phdr) {
            lock_release(&file_lock);
            goto done;
        }
        lock_release(&file_lock);

		file_ofs += sizeof phdr;
		switch (phdr.p_type) {
			case PT_NULL:
			case PT_NOTE:
			case PT_PHDR:
			case PT_STACK:
			default:
				/* Ignore this segment. */
				break;
			case PT_DYNAMIC:
			case PT_INTERP:
			case PT_SHLIB:
				goto done;
			case PT_LOAD:
				if (validate_segment (&phdr, file)) {
					bool writable = (phdr.p_flags & PF_W) != 0;
					uint64_t file_page = phdr.p_offset & ~PGMASK;
					uint64_t mem_page = phdr.p_vaddr & ~PGMASK;
					uint64_t page_offset = phdr.p_vaddr & PGMASK;
					uint32_t read_bytes, zero_bytes;
					if (phdr.p_filesz > 0) {
						/* Normal segment.
						 * Read initial part from disk and zero the rest. */
						read_bytes = page_offset + phdr.p_filesz;
						zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
								- read_bytes);
					} else {
						/* Entirely zero.
						 * Don't read anything from disk. */
						read_bytes = 0;
						zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
					}
					if (!load_segment (file, file_page, (void *) mem_page, read_bytes, zero_bytes, writable)) {
                        goto done;
                    }

				}
				else {
					goto done;
                }
				break;
		}
	}

	/* Set up stack. */
	if (!setup_stack (if_))
		goto done;

	/* Start address. */
	if_->rip = ehdr.e_entry;


    /* PROJECT 2: ARGUMENT PASSING */
    uintptr_t stack_pointer = (if_->rsp);

    /* 4단계: 문자열 넣기 */
    char *address[40];

    for(int i = argc-1; i >= 0; i--) {
        uintptr_t len = strlen(args[i]) + 1;   // '\0' 포함
        stack_pointer -= len;
        address[i] = stack_pointer;
        memcpy((stack_pointer), args[i], len);
    }

    /* 3단계: word align (8byte) 단위로 주소 맞춰주기 */
    uintptr_t word_align;
    int align = (argc % 2 == 0) ? PTR_SIZE : PTR_SIZE * 2;
    word_align = ((stack_pointer) % align);
    stack_pointer -= word_align;
    memset((stack_pointer), '\0', word_align);

    /* 2단계: 문자열 주소값 넣어주기 */
    stack_pointer -= PTR_SIZE;
    memset((stack_pointer), '\0', PTR_SIZE); // argv[4] '\0'
    for(int i = argc-1; i >= 0; i--) {
        stack_pointer -= PTR_SIZE;
        memcpy((stack_pointer), (&address[i]), PTR_SIZE);
    }

    /* 1단계: 가짜 return address 넣어주기 */
    stack_pointer -= PTR_SIZE;
    memset((stack_pointer), '\0', PTR_SIZE);

    /* 0단계: RDI = argc, 
             RSI = 가짜 return address 이전 주소 */
    if_->rsp = stack_pointer;            // 저장된 스택 주소를 내려주는 작업을 마지막에 해주었다.
    if_->R.rdi = argc;
    if_->R.rsi = if_->rsp + PTR_SIZE;

    lock_acquire(&file_lock);
    file_deny_write(file);
    lock_release(&file_lock);

    t->my_exec_file = file;
	success = true;
    return success;
done:
	/* We arrive here whether the load is successful or not. */
    if(!success) {
        lock_acquire(&file_lock);
        file_close(file);
        lock_release(&file_lock);
    }
	return success;
}


/* Checks whether PHDR describes a valid, loadable segment in
 * FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Phdr *phdr, struct file *file) {
	/* p_offset and p_vaddr must have the same page offset. */
	if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
		return false;

	/* p_offset must point within FILE. */
	if (phdr->p_offset > (uint64_t) file_length (file))
		return false;

	/* p_memsz must be at least as big as p_filesz. */
	if (phdr->p_memsz < phdr->p_filesz)
		return false;

	/* The segment must not be empty. */
	if (phdr->p_memsz == 0)
		return false;

	/* The virtual memory region must both start and end within the
	   user address space range. */
	if (!is_user_vaddr ((void *) phdr->p_vaddr))
		return false;
	if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
		return false;

	/* The region cannot "wrap around" across the kernel virtual
	   address space. */
	if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
		return false;

	/* Disallow mapping page 0.
	   Not only is it a bad idea to map page 0, but if we allowed
	   it then user code that passed a null pointer to system calls
	   could quite likely panic the kernel by way of null pointer
	   assertions in memcpy(), etc. */
	if (phdr->p_vaddr < PGSIZE)
		return false;

	/* It's okay. */
	return true;
}

#ifndef VM
/* Codes of this block will be ONLY USED DURING project 2.
 * If you want to implement the function for whole project 2, implement it
 * outside of #ifndef macro. */

/* load() helpers. */
static bool install_page (void *upage, void *kpage, bool writable);

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

    lock_acquire(&file_lock);
	file_seek (file, ofs);
    lock_release(&file_lock);

	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* Get a page of memory. */
		uint8_t *kpage = palloc_get_page (PAL_USER);
		if (kpage == NULL){
            return false;
        }

		/* Load this page. */
        lock_acquire(&file_lock);
		if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes) {
            lock_release(&file_lock);
			palloc_free_page (kpage);
			return false;
		}
        lock_release(&file_lock);
		memset (kpage + page_read_bytes, 0, page_zero_bytes);

		/* Add the page to the process's address space. */
		if (!install_page (upage, kpage, writable)) {
			printf("fail\n");
			palloc_free_page (kpage);
			return false;
		}

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a minimal stack by mapping a zeroed page at the USER_STACK */
static bool
setup_stack (struct intr_frame *if_) {
	uint8_t *kpage;
	bool success = false;

	kpage = palloc_get_page (PAL_USER | PAL_ZERO);
	if (kpage != NULL) {
		success = install_page (((uint8_t *) USER_STACK) - PGSIZE, kpage, true);
		if (success)
			if_->rsp = USER_STACK;
		else
			palloc_free_page (kpage);
	}
	return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
 * virtual address KPAGE to the page table.
 * If WRITABLE is true, the user process may modify the page;
 * otherwise, it is read-only.
 * UPAGE must not already be mapped.
 * KPAGE should probably be a page obtained from the user pool
 * with palloc_get_page().
 * Returns true on success, false if UPAGE is already mapped or
 * if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable) {
	struct thread *t = thread_current ();

	/* Verify that there's not already a page at that virtual
	 * address, then map our page there. */
	return (pml4_get_page (t->pml4, upage) == NULL
			&& pml4_set_page (t->pml4, upage, kpage, writable));
}
#else
/* From here, codes will be used after project 3.
 * If you want to implement the function for only project 2, implement it on the
 * upper block. */

static bool
lazy_load_segment (struct page *page, void *aux) {
    struct lazy_args *args = (struct lazy_args *)aux;
    struct file *file = args->file;
    off_t ofs = args->file_ofs;
    size_t read_bytes = args->read_bytes;
    size_t zero_bytes = args->zero_bytes;
    bool file_lock_holder = lock_held_by_current_thread(&file_lock);
    bool success = true;

	/* TODO: Load the segment from the file */
	/* TODO: This called when the first page fault occurs on address VA. */
	/* TODO: VA is available when calling this function. */
    if(!file_lock_holder) lock_acquire(&file_lock);

    file_seek(file, ofs);
    if (file_read (file, page->va, read_bytes) != (int) read_bytes) {
        success = false;
    }

    if(!file_lock_holder) lock_release(&file_lock);
    
    if(success) {
        memset (page->va + read_bytes, 0, zero_bytes);
    }
    
    return success;
}

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

    size_t file_offset = ofs;

	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* Set up aux to pass information to the lazy_load_segment. */
        struct lazy_args *la = malloc(sizeof(struct lazy_args));
        *la = (struct lazy_args) {
            .file = file,
            .file_ofs = file_offset,
            .read_bytes = page_read_bytes,
            .zero_bytes = page_zero_bytes
        };
		void *aux = (void *)la;
        
		if (!vm_alloc_page_with_initializer (VM_ANON, upage, writable, lazy_load_segment, aux)) {
            return false;
        }

		/* Advance. */
        file_offset += page_read_bytes;
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a PAGE of stack at the USER_STACK. Return true on success. */
static bool
setup_stack (struct intr_frame *if_) {
	bool success = false;
	void *stack_bottom = (void *) (((uint8_t *) USER_STACK) - PGSIZE);

	/* TODO: Map the stack on stack_bottom and claim the page immediately.
	 * TODO: If success, set the rsp accordingly.
	 * TODO: You should mark the page is stack. */
	/* TODO: Your code goes here */
    if(vm_alloc_page(VM_STACK | VM_ANON, stack_bottom, true)) {
        success = vm_claim_page(stack_bottom);
        if(success) {
            if_->rsp = USER_STACK;
        }
    }

	return success;
}
#endif /* VM */
