// kernel type definitions (for ALL types)
// this gets generated from the kernel's BTF
#include "vmlinux.h"

// macros for CO-RE and BPF ops via libbpf
#include <bpf/bpf_helpers.h>

// CO-RE macro for reading kernel structs
#include <bpf/bpf_core_read.h>

// helpers for attaching to tracepoints
#include <bpf/bpf_tracing.h>

#include "common.h"

// need to declare license - GPL for most BPF helpers
// SEC is a macro that defines the ELF section name
char LICENSE[] SEC("license") = "GPL";

// define ring buffer map for sending events to user-space
// more efficient than perf buffers for high-throughput
// default choice unless legacy or NMI
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);

    // size: must be power of 2 + page aligned
    __uint(max_entries, 256 * 1024); // 256 KB = ~1000 events in buffer
} events SEC(".maps");

// format for attachment point is: tp/<category>/<tracepoint_name>
SEC("tp/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx) {
    struct event *e;

    // get current task struct via CO-RE
    // returns a u64/void* that needs to be cast 
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    // reserve space in ring buffer - must handle NULL case (when buffer is full)
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        // just dropping event for now
        return 0;
    }

    // func returns pid << 32 } tgid
    // lower 32 bits needed bc tgid in kernel = pid in userspace
    e->pid = bpf_get_current_pid_tgid() >> 32;

    // func returns gid << 32 | uid
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    // get the process command name, ex: 'ls', 'ps'
    // copy of TASK_COMM_LEN bytes
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // read the filename arg from the execve syscall
    // pointer to filename string is contained in ctx->args[0]
    // the func is meant for user space strings - returns bytes read + handles page faults
    const char *filename_ptr = (const char *)ctx->args[0];
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename_ptr);

    // submit even to ring buffer so its visible to user space
    bpf_ringbuf_submit(e, 0);
}