#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

#define PTR_SIZE 8
#define EXIT_FALSE -2

tid_t process_create_initd (const char *file_name);
tid_t process_fork (const char *name, struct intr_frame *if_);
int process_exec (void *f_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (struct thread *next);

struct child_list_elem* process_set_child_list(struct thread *parent, struct thread *child);
int get_child_exit_status(struct thread* parent, tid_t child_tid);
#endif /* userprog/process.h */
