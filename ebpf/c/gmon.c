#include "vmlinux.h"
#include "maps.h"
#include "goroutine.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// read_stack_id reads the stack id from stack trace map.
// 1 on failure
static __always_inline int read_stack_id(struct pt_regs *ctx, int *stack_id) {
    int id = bpf_get_stackid(ctx, &stack_addresses, BPF_F_USER_STACK);
    if (id < 0) {
        return 1;
    }
    *stack_id = id;
    return 0;
}

SEC("uretprobe/runtime.newproc1")
int runtime_newproc1(struct pt_regs *ctx) {
    void *newg_p = (void *)PT_REGS_RC_CORE(ctx);
    if (newg_p == NULL) {
        bpf_printk("%s:%d | failed to extract new goroutine pointer from retval\n", __FILE__, __LINE__);
        return 0;
    }
    // `pahole -C runtime.g /path/to/gobinary 2>/dev/null` shows the offsets of the goid.
    int64_t goid = 0;
    if (bpf_core_read_user(&goid, sizeof(int64_t), newg_p + 160)) {
        bpf_printk("%s:%d | failed to read goroutine id from newg with the offset\n", __FILE__, __LINE__);
        return 0;
    }
    if (goid == 0) {
        bpf_printk("%s:%d | goroutine id is zero\n", __FILE__, __LINE__);
        return 0;
    }
    int stack_id = 0;
    if (read_stack_id(ctx, &stack_id)) {
        bpf_printk("%s:%d | failed to read stackid\n", __FILE__, __LINE__);
        return 0;
    }

    struct event *ev;
    ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev) {
        bpf_printk("%s:%d | failed to reserve ringbuf\n", __FILE__, __LINE__);
        return 0;
    }
    ev->goroutine_id = goid;
    ev->stack_id = stack_id;
    ev->exit = false;
    bpf_ringbuf_submit(ev, 0);

    return 0;
}

SEC("uprobe/runtime.goexit1")
int runtime_goexit1(struct pt_regs *ctx) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    int64_t go_id = 0;
    if (read_goroutine_id(task, &go_id)) {
        bpf_printk("%s:%d | failed to read goroutine id\n", __FILE__, __LINE__);
        return 0;
    }

    int stack_id = 0;
    if (read_stack_id(ctx, &stack_id)) {
        bpf_printk("%s:%d | failed to read stackid\n", __FILE__, __LINE__);
        return 0;
    }

    struct event *ev;
    ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev) {
        bpf_printk("%s:%d | failed to reserve ringbuf\n", __FILE__, __LINE__);
        return 0;
    }
    ev->goroutine_id = go_id;
    ev->stack_id = stack_id;
    ev->exit = true;
    bpf_ringbuf_submit(ev, 0);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
