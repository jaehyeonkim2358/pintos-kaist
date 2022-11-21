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

#include <stdlib.h>

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

#define SYSCALL_CNT 25

struct arguments {
    uint64_t syscall_num;
    uint64_t arg1, arg2, arg3, arg4, arg5, arg6;
};

struct system_call {
    uint64_t syscall_num;
    void (*function) (struct arguments *args);
};


void halt_handler(struct arguments *args);
void exit_handler(struct arguments *args);
void fork_handler(struct arguments *args);
void exec_handler(struct arguments *args);
void wait_handler(struct arguments *args);
void create_handler(struct arguments *args);
void remove_handler(struct arguments *args);
void open_handler(struct arguments *args);
void filesize_handler(struct arguments *args);
void read_handler(struct arguments *args);
void write_handler(struct arguments *args);
void seek_handler(struct arguments *args);
void tell_handler(struct arguments *args);
void close_handler(struct arguments *args);
void mmap_handler(struct arguments *args);
void mnumap_handler(struct arguments *args);
void chdir_handler(struct arguments *args);
void mkdir_handler(struct arguments *args);
void readdir_handler(struct arguments *args);
void isdir_handler(struct arguments *args);
void inumber_handler(struct arguments *args);
void symlink_handler(struct arguments *args);
void dup2_handler(struct arguments *args);
void mount_handler(struct arguments *args);
void umount_handler(struct arguments *args);


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

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
    
    struct arguments args;
    args.syscall_num = f->R.rax;
    args.arg1 = f->R.rdi;
    args.arg2 = f->R.rsi;
    args.arg3 = f->R.rdx;
    args.arg4 = f->R.r10;
    args.arg5 = f->R.r8;
    args.arg6 = f->R.r9;

    struct system_call call = syscall_list[args.syscall_num];
    if(call.syscall_num == args.syscall_num) {
        call.function(&args);
    }
}


void halt_handler(struct arguments *args) {
    power_off();
}

void exit_handler(struct arguments *args) {
    int status = args->arg1;
    thread_current()->process_status = status;
    thread_exit ();
}

void fork_handler(struct arguments *args) {

}

void exec_handler(struct arguments *args) {

}

void wait_handler(struct arguments *args) {

}

void create_handler(struct arguments *args) {

}

void remove_handler(struct arguments *args) {

}

void open_handler(struct arguments *args) {

}

void filesize_handler(struct arguments *args) {

}

void read_handler(struct arguments *args) {

}

void write_handler(struct arguments *args) {
    int fd = args->arg1;
    char *buffer = args->arg2;
    unsigned size = args->arg3;
    printf("%s", buffer);
}

void seek_handler(struct arguments *args) {

}

void tell_handler(struct arguments *args) {

}

void close_handler(struct arguments *args) {

}

void mmap_handler(struct arguments *args) {

}

void mnumap_handler(struct arguments *args) {

}

void chdir_handler(struct arguments *args) {

}

void mkdir_handler(struct arguments *args) {

}
void readdir_handler(struct arguments *args) {
    
}

void isdir_handler(struct arguments *args) {
    
}
void inumber_handler(struct arguments *args) {
    
}
void symlink_handler(struct arguments *args) {
    
}
void dup2_handler(struct arguments *args) {
    
}
void mount_handler(struct arguments *args) {
    
}
void umount_handler(struct arguments *args) {
    
}