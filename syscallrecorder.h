#ifndef __SYSCALLRECORDER_H
#define __SYSCALLRECORDER_H

#define MAX_ENTRIES 1024

struct data_t {
    unsigned int syscall_id;
    unsigned long long count;
    unsigned long long count_failed;
};

struct event_t {
    unsigned int stop;
};

#endif /* __SYSCALLRECORDER_H */
