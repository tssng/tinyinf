// definitions shared by both eBPF and user-space programs
#ifndef __COMMON_H
#define __COMMON_H

// max length of a command name 
// (its also the name shown when running smth like ps/top
#define TASK_COMM_LEN 16

// max length for filename storage 
#define MAX_FILENAME_LEN 256

// (aligned) struct passed between eBPF and user-space via ring buffer
struct event {
    __u32 pid; // process id
    __u32 uid; // user id of process owner
    char comm[TASK_COMM_LEN]; // command/executable name
    char filename[MAX_FILENAME_LEN]; // filename of executed binary
}

#endif


