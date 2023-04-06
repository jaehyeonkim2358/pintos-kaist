#include "userprog/syscall.h"

#include <stdio.h>
#include <stdlib.h>
#include <syscall-nr.h>

#include "filesys/file.h"
#include "filesys/filesys.h"
#include "filesys/fsutil.h"
#include "intrinsic.h"
#include "lib/string.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/loader.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/gdt.h"
#include "userprog/process.h"
#include "vm/vm.h"

void syscall_entry(void);
void syscall_handler(struct intr_frame *);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual.
 *
 * 이전에 system call 서비스는 interrupt handler에 의해 핸들링 되었습니다.
 * 그러나 x86-64부터 system call 요청을 위해 'syscall'이라는 인스트럭션을 통한 특별한 경로가 제공됩니다.
 *
 * 'syscall' 인스트럭션은 Model Specific Register(MSR)에서 값을 읽어오며 동작합니다.
 * 자세한 내용은 메뉴얼을 참고해주세용.
 * */

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

bool address_check(bool write, char *ptr);
bool mmap_check(char *ptr, size_t length, off_t offset);
int fd_table_get_fd(struct file *_file);
struct file *fd_table_get_file(int fd);
int fd_table_insert(struct file *_file);
void fd_table_remove(int fd);

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
    {SYS_UMOUNT, umount_handler}};

void syscall_init(void) {
    write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48 |
                            ((uint64_t)SEL_KCSEG) << 32);
    write_msr(MSR_LSTAR, (uint64_t)syscall_entry);

    /* The interrupt service rountine should not serve any interrupts
     * until the syscall_entry swaps the userland stack to the kernel
     * mode stack. Therefore, we masked the FLAG_FL. */
    write_msr(MSR_SYSCALL_MASK,
              FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);

    lock_init(&file_lock);
}

/* The main system call interface */
void syscall_handler(struct intr_frame *f) {
    ASSERT(F_RAX < SYSCALL_CNT);

    struct system_call syscall = syscall_list[F_RAX];

    if (syscall.syscall_num == F_RAX) {
        syscall.function(f);
    } else {
        PANIC("syscall_list index와 syscall number가 일치하지 않음");
    }
}

/* PROJECT 2: SYSTEM CALLS */
void halt_handler(struct intr_frame *f UNUSED) {
    power_off();
}

void exit_handler(struct intr_frame *f) {
    int status = (int)F_ARG1;
    thread_current()->exit_status = status;
    F_RAX = status;
    thread_exit();
}

void fork_handler(struct intr_frame *f) {
    const char *thread_name = (char *)F_ARG1;
    F_RAX = process_fork(thread_name, f);
}

void exec_handler(struct intr_frame *f) {
    char *file_name = (char *)F_ARG1;
    char *new_fname;

    if (!address_check(false, file_name)) kern_exit(f, -1);

    new_fname = palloc_get_page(0);
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

    if (file_name == NULL) kern_exit(f, -1);
    if (!address_check(false, file_name)) kern_exit(f, -1);

    lock_acquire(&file_lock);
    F_RAX = filesys_create(file_name, initial_size);
    lock_release(&file_lock);
}

void remove_handler(struct intr_frame *f) {
    F_RAX = false;

    char *file = (char *)F_ARG1;
    if (file == NULL) return;
    if (strlen(file) == 0) return;

    lock_acquire(&file_lock);
    F_RAX = filesys_remove(file);
    lock_release(&file_lock);
}

void open_handler(struct intr_frame *f) {
    F_RAX = -1;
    char *file_name = (char *)F_ARG1;
    struct file *o_file = NULL;
    int fd = -1;

    if (file_name == NULL) kern_exit(f, -1);
    if (!address_check(false, file_name)) kern_exit(f, -1);

    lock_acquire(&file_lock);
    o_file = filesys_open(file_name);
    lock_release(&file_lock);

    if (o_file == NULL) return;

    fd = fd_table_insert(o_file);

    /* fd_table에 저장 실패시 file close */
    if (fd == -1) {
        lock_acquire(&file_lock);
        file_close(o_file);
        lock_release(&file_lock);
    }
    F_RAX = fd;
}

void filesize_handler(struct intr_frame *f) {
    int fd = F_ARG1;
    struct file *file_ = fd_table_get_file(fd);
    if (file_ == NULL) return;

    lock_acquire(&file_lock);
    F_RAX = file_length(file_);
    lock_release(&file_lock);
}

void read_handler(struct intr_frame *f) {
    int fd = F_ARG1;
    void *buffer = (void *)F_ARG2;
    unsigned size = F_ARG3;

    if (fd < 0 || FDLIST_LEN <= fd) kern_exit(f, -1);
    if (fd == 1) kern_exit(f, -1);
    if (!address_check(true, buffer)) kern_exit(f, -1);
    if (!address_check(true, buffer + size - 1)) kern_exit(f, -1);

    struct file *file_ = fd_table_get_file(fd);
    if (file_ == NULL) return;

    lock_acquire(&file_lock);
    size = file_read(file_, buffer, size);
    lock_release(&file_lock);

    F_RAX = size;
}

void write_handler(struct intr_frame *f) {
    int fd = (int)F_ARG1;
    char *buffer = (char *)F_ARG2;
    unsigned size = F_ARG3;

    if (fd <= 0) return;

    if (!address_check(false, buffer)) kern_exit(f, -1);
    if (!address_check(false, buffer + size - 1)) kern_exit(f, -1);

    if (fd == 1) {
        if (size > 0) {
            if (strlen(buffer) > size) {
                char new_buf[size];
                strlcpy(new_buf, buffer, size);
                printf("%s", new_buf);
            } else {
                printf("%s", buffer);
            }
        } else {
            size = 0;
        }
    } else {
        struct file *file_ = fd_table_get_file(fd);
        if (file_ == NULL) return;

        lock_acquire(&file_lock);
        size = file_write(file_, buffer, size);
        lock_release(&file_lock);
    }

    F_RAX = size;
}

void seek_handler(struct intr_frame *f) {
    int fd = (int)F_ARG1;
    unsigned position = (unsigned)F_ARG2;
    struct file *getfile = NULL;

    getfile = fd_table_get_file(fd);
    if (getfile == NULL) kern_exit(f, -1);

    lock_acquire(&file_lock);
    file_seek(getfile, position);
    lock_release(&file_lock);
}

void tell_handler(struct intr_frame *f) {
    int fd = F_ARG1;
    struct file *tell_file = fd_table_get_file(fd);
    if (tell_file == NULL) kern_exit(f, -1);

    lock_acquire(&file_lock);
    F_RAX = file_tell(tell_file);
    lock_release(&file_lock);
}

void close_handler(struct intr_frame *f) {
    int fd = F_ARG1;
    struct file *file_ = fd_table_get_file(fd);
    if (file_ == NULL) return;

    lock_acquire(&file_lock);
    file_close(file_);
    lock_release(&file_lock);

    fd_table_remove(fd);
}

/* PROJECT3 */
void mmap_handler(struct intr_frame *f) {
    void *addr = (void *)F_ARG1;
    size_t length = (size_t)F_ARG2;
    int writable = (int)F_ARG3;
    int fd = (int)F_ARG4;
    off_t offset = (off_t)F_ARG5;
    void *result = NULL;
    struct file *file_ = fd_table_get_file(fd);

    if (file_ == NULL) kern_exit(f, -1);

    if (mmap_check(addr, length, offset)) {
        lock_acquire(&file_lock);
        result = do_mmap(addr, length, writable, file_, offset);
        lock_release(&file_lock);
    }

    F_RAX = (uint64_t)result;
}

void mnumap_handler(struct intr_frame *f) {
    void *addr = (void *)F_ARG1;
    if (!address_check(false, addr)) kern_exit(f, -1);
    if (addr == pg_round_down(addr)) {
        do_munmap(addr);
    }
}

void chdir_handler(struct intr_frame *f UNUSED) {
}

void mkdir_handler(struct intr_frame *f UNUSED) {
    char *dir = (char *)F_ARG1;
}

void readdir_handler(struct intr_frame *f UNUSED) {
}

void isdir_handler(struct intr_frame *f UNUSED) {
}

void inumber_handler(struct intr_frame *f UNUSED) {
}

void symlink_handler(struct intr_frame *f UNUSED) {
}

void dup2_handler(struct intr_frame *f UNUSED) {
}

void mount_handler(struct intr_frame *f UNUSED) {
}

void umount_handler(struct intr_frame *f UNUSED) {
}

/* system call handler helper */
bool address_check(bool write, char *ptr) {
    struct thread *curr = thread_current();
    struct page *p = NULL;

    if (ptr == NULL) {
        return false;
    }

    p = spt_find_page(&curr->spt, ptr);
    if (p == NULL) {
        return false;
    } else {
        if (write && !p->writable) {
            return false;
        }
    }
    return true;
}

bool mmap_check(char *ptr, size_t length, off_t offset) {
    struct thread *curr = thread_current();

    if (length == 0) return false;
    if (offset % PGSIZE != 0) return false;
    if (ptr != pg_round_down(ptr)) return false;
    if (is_kernel_vaddr(ptr)) return false;
    if (is_kernel_vaddr(ptr - length)) return false;

    while (length > 0) {
        if (spt_find_page(&curr->spt, ptr) != NULL) {
            return false;
        }
        length -= length > PGSIZE ? PGSIZE : length;
        ptr -= PGSIZE;
    }

    return true;
}

void kern_exit(struct intr_frame *f, int status) {
    F_ARG1 = status;
    exit_handler(f);
    NOT_REACHED();
}

int fd_table_get_fd(struct file *_file) {
    for (int i = 3; i < FDLIST_LEN; i++) {
        if ((thread_current()->fd_table)[i] == NULL) continue;
        if ((thread_current()->fd_table)[i] == _file) {
            return i;
        }
    }
    return -1;
}

int fd_table_insert(struct file *_file) {
    for (int i = 3; i < FDLIST_LEN; i++) {
        if ((thread_current()->fd_table)[i] == NULL) {
            (thread_current()->fd_table)[i] = _file;
            return i;
        }
    }
    return -1;
}

void fd_table_remove(int fd) {
    if (fd < 3 || fd >= FDLIST_LEN) return;
    (thread_current()->fd_table)[fd] = NULL;
}

struct file *
fd_table_get_file(int fd) {
    if (fd < 3 || fd >= FDLIST_LEN) return NULL;
    return (thread_current()->fd_table)[fd];
}
