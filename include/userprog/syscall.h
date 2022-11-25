#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/interrupt.h"

void syscall_init (void);


/* PROJECT 2: SYSTEM CALLS */
#define SYSCALL_CNT 25

/* PROJECT 2: SYSTEM CALLS */
struct system_call {
    uint64_t syscall_num;
    void (*function) (struct intr_frame *f);
};

/* PROJECT 2: SYSTEM CALLS */
void halt_handler(struct intr_frame *f);
void exit_handler(struct intr_frame *f);
void fork_handler(struct intr_frame *f);
void exec_handler(struct intr_frame *f);
void wait_handler(struct intr_frame *f);
void create_handler(struct intr_frame *f);
void remove_handler(struct intr_frame *f);
void open_handler(struct intr_frame *f);
void filesize_handler(struct intr_frame *f);
void read_handler(struct intr_frame *f);
void write_handler(struct intr_frame *f);
void seek_handler(struct intr_frame *f);
void tell_handler(struct intr_frame *f);
void close_handler(struct intr_frame *f);
void mmap_handler(struct intr_frame *f);
void mnumap_handler(struct intr_frame *f);
void chdir_handler(struct intr_frame *f);
void mkdir_handler(struct intr_frame *f);
void readdir_handler(struct intr_frame *f);
void isdir_handler(struct intr_frame *f);
void inumber_handler(struct intr_frame *f);
void symlink_handler(struct intr_frame *f);
void dup2_handler(struct intr_frame *f);
void mount_handler(struct intr_frame *f);
void umount_handler(struct intr_frame *f);

void kern_exit(struct intr_frame *f, int status);

#endif /* userprog/syscall.h */
