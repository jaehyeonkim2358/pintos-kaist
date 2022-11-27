#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "threads/init.h"
#include "devices/input.h"

#include <stdlib.h>

#include "userprog/process.h"
#include "lib/string.h"
#include "filesys/fsutil.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "lib/kernel/console.h"
#include "threads/vaddr.h"
#include "threads/palloc.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);



/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

#define F_RAX f->R.rax
#define F_ARG1 f->R.rdi
#define F_ARG2 f->R.rsi
#define F_ARG3 f->R.rdx
#define F_ARG4 f->R.r10
#define F_ARG5 f->R.r8
#define F_ARG6 f->R.r9

bool address_check(char *ptr);

int fd_list_get_fd(struct file *_file);
struct file *fd_list_get_file(int fd);
int fd_list_insert(struct file *_file);
void fd_list_remove(int fd);

struct system_call syscall_list[] = {
        {SYS_HALT, halt_handler}, 
        {SYS_EXIT, exit_handler},
        {SYS_FORK, fork_handler},
        {SYS_EXEC, exec_handler},
        {SYS_WAIT, wait_handler},
        {SYS_CREATE, create_handler},
        {SYS_REMOVE, remove_handler},
        {SYS_OPEN, open_handler},
        {SYS_FILESIZE, filesize_handler},
        {SYS_READ, read_handler},
        {SYS_WRITE, write_handler},
        {SYS_SEEK, seek_handler},
        {SYS_TELL, tell_handler},
        {SYS_CLOSE, close_handler},
        {SYS_MMAP, mmap_handler},
        {SYS_MUNMAP, mnumap_handler},
        {SYS_CHDIR, chdir_handler},
        {SYS_MKDIR, mkdir_handler},
        {SYS_READDIR, readdir_handler},
        {SYS_ISDIR, isdir_handler},
        {SYS_INUMBER, inumber_handler},
        {SYS_SYMLINK, symlink_handler},
        {SYS_DUP2, dup2_handler},
        {SYS_MOUNT, mount_handler},
        {SYS_UMOUNT, umount_handler}
    };


void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

    lock_init(&file_lock);
    use_file_read_lock = true;
	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f) {
    ASSERT(0 <= F_RAX && F_RAX < SYSCALL_CNT);

    struct system_call syscall = syscall_list[F_RAX];

    if(syscall.syscall_num == F_RAX) {
        syscall.function(f);
    } else {
        printf("굉장히 잘못된 그 저기 그거..\n");
    }
}

/* PROJECT 2: SYSTEM CALLS */
void halt_handler(struct intr_frame *f) {
    power_off();
}

void exit_handler(struct intr_frame *f) {
    int status = (int)F_ARG1;
    thread_current()->process_status = status;
    F_RAX = thread_current()->process_status;
    thread_exit ();
}

void fork_handler(struct intr_frame *f) {
    const char *thread_name = (char *)F_ARG1;
    F_RAX = process_fork (thread_name, f);
}

void exec_handler(struct intr_frame *f) {
    char *file_name = (char *)F_ARG1;
    char *new_fname;

    if(!address_check(file_name)) kern_exit(f, -1);

    new_fname = palloc_get_page (0);
    strlcpy(new_fname, file_name, PGSIZE);
    F_RAX = process_exec(new_fname);
}

void wait_handler(struct intr_frame *f) {
    tid_t pid = F_ARG1;
    F_RAX = process_wait(pid);
}

void create_handler(struct intr_frame *f) {
    F_RAX = false;

    char *file_name = (char *)F_ARG1;
    off_t initial_size = (off_t)F_ARG2;

    if(file_name == NULL) kern_exit(f, -1);
    if(!address_check(file_name)) kern_exit(f, -1);
    
    acquire_file_lock(&file_lock);
    F_RAX = filesys_create(file_name, initial_size);
    release_file_lock(&file_lock);
}

void remove_handler(struct intr_frame *f) {
    F_RAX = false;

    char *file = (char *)F_ARG1;
    if(file == NULL) return;
    if(strlen(file) == 0) return;

    acquire_file_lock(&file_lock);
    F_RAX = filesys_remove(file);
    release_file_lock(&file_lock);
}

void open_handler(struct intr_frame *f) {
    F_RAX = -1;
    char *file_name = (char *)F_ARG1;
    struct file *o_file = NULL;
    int fd = -1;
    
    if(file_name == NULL)  return;
    if(!address_check(file_name)) kern_exit(f, -1);

    acquire_file_lock(&file_lock);
    o_file = filesys_open(file_name);
    release_file_lock(&file_lock);

    if(o_file == NULL) return;
    if((fd = fd_list_insert(o_file)) == -1) kern_exit(f, -1);

    F_RAX = fd;
}

void filesize_handler(struct intr_frame *f) {
    int fd = F_ARG1;
    struct file *file_ = fd_list_get_file(fd);
    if(file_ == NULL) return;

    acquire_file_lock(&file_lock);
    F_RAX = file_length(file_);
    release_file_lock(&file_lock);
}

void read_handler(struct intr_frame *f) {
    int fd = F_ARG1;
    char *buffer = (char *)F_ARG2;
    unsigned size = F_ARG3;
    int32_t read_byte = 0;
    int i = 0;

    if(fd < 0 || FDLIST_LEN <= fd) return;
    if(fd == 1)  return;
    if(!address_check(buffer)) kern_exit(f, -1);

    if(fd == STDIN_FILENO) {
        acquire_file_lock(&file_lock);
        while(size-- > 0) {
            buffer[i++] = (char) input_getc();
            read_byte++;
        }
        F_RAX = read_byte;
        release_file_lock(&file_lock);
    } else {
        struct file *file_ = fd_list_get_file(fd);
        if(file_ == NULL) return;

        acquire_file_lock(&file_lock);
        F_RAX = file_read(file_, buffer, size);
        release_file_lock(&file_lock);
    }
}

void write_handler(struct intr_frame *f) {
    int fd = (int)F_ARG1;
    char *buffer = (char *)F_ARG2;
    unsigned size = F_ARG3;

    if(fd <= 0 || fd >= FDLIST_LEN) return;
    if(!address_check(buffer)) kern_exit(f, -1);

    if(fd == 1) {
        putbuf(buffer, size);
    } else {
        struct file *file_ = fd_list_get_file(fd);
        if(file_ == NULL) return;
        acquire_file_lock(&file_lock);
        size = file_write(file_, buffer, size);
        release_file_lock(&file_lock);
    }
    F_RAX = size;
}

void seek_handler(struct intr_frame *f) {
    int fd = (int)F_ARG1;
    unsigned position = (unsigned)F_ARG2;
    struct file *getfile = fd_list_get_file(fd);
    if(getfile == NULL) kern_exit(f, -1);

    acquire_file_lock(&file_lock);
    file_seek(getfile, position);
    release_file_lock(&file_lock);
}

void tell_handler(struct intr_frame *f) {
    int fd = (int)F_ARG1;
    struct file *tell_file = fd_list_get_file(fd);
    if(tell_file == NULL) kern_exit(f, -1);

    acquire_file_lock(&file_lock);
    F_RAX = file_tell(tell_file);
    release_file_lock(&file_lock);
}

void close_handler(struct intr_frame *f) {
    int fd = F_ARG1;
    struct file *file_ = fd_list_get_file(fd);
    if(file_ == NULL) return;

    fd_list_remove(fd);

    acquire_file_lock(&file_lock);
    file_close(file_);
    release_file_lock(&file_lock);
}


/* PROJECT3 ~~~~~ */
void mmap_handler(struct intr_frame *f) {

}

void mnumap_handler(struct intr_frame *f) {

}

void chdir_handler(struct intr_frame *f) {

}

void mkdir_handler(struct intr_frame *f) {

}

void readdir_handler(struct intr_frame *f) {
    
}

void isdir_handler(struct intr_frame *f) {
    
}

void inumber_handler(struct intr_frame *f) {
    
}

void symlink_handler(struct intr_frame *f) {
    
}

void dup2_handler(struct intr_frame *f) {
    
}

void mount_handler(struct intr_frame *f) {
    
}

void umount_handler(struct intr_frame *f) {
    
}


/* 여기서 부터는 system call handler 아님 */
bool
address_check(char *ptr) {
    return pml4_get_page(thread_current()->pml4, ptr) != NULL;
}


void 
kern_exit(struct intr_frame *f, int status) {
    F_ARG1 = status;
    exit_handler(f);
    NOT_REACHED();
}


int
fd_list_get_fd(struct file *_file) {
    for(int i = 3; i < FDLIST_LEN; i++) {
        if((thread_current()->fd_list)[i] == NULL) continue;
        if((thread_current()->fd_list)[i] == _file) {
            return i;
        }
    }
    return -1;
}


int
fd_list_insert(struct file *_file) {
    for(int i = 3; i < FDLIST_LEN; i++) {
        if((thread_current()->fd_list)[i] == NULL) {
            (thread_current()->fd_list)[i] = _file;
            return i;
        }
    }
    return -1;
}


void
fd_list_remove(int fd) {
    if(fd < 3 || fd >= FDLIST_LEN) return;
    (thread_current()->fd_list)[fd] = NULL;
}


struct file *
fd_list_get_file(int fd) {
    if(fd < 3 || fd >= FDLIST_LEN) return NULL;
    return (thread_current()->fd_list)[fd];
}


void
acquire_file_lock (struct lock *flie_lock) {
	// if (!intr_context () && use_file_read_lock) {
	// 	if (lock_held_by_current_thread (flie_lock)) 
	// 		file_read_lock_depth++; 
	// 	else
	// 		lock_acquire (flie_lock); 
	// }
    lock_acquire (flie_lock); 
}

void
release_file_lock (struct lock *flie_lock) {
	// if (!intr_context () && use_file_read_lock) {
	// 	if (file_read_lock_depth > 0)
	// 		file_read_lock_depth--;
	// 	else
	// 		lock_release (flie_lock); 
	// }
    lock_release (flie_lock); 
}