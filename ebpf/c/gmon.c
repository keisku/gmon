#include "vmlinux.h"
#include "maps.h"

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
        bpf_printk("runtime.newproc1 | failed to extract new goroutine pointer from retval\n");
        return 0;
    }
    // `pahole -C runtime.g /path/to/gobinary 2>/dev/null` shows the offsets of the goid which is 152.
    int64_t goid = 0;
    if (bpf_core_read_user(&goid, sizeof(int64_t), newg_p + 152)) {
        bpf_printk("runtime.newproc1 | failed to extract goroutine id from newg with the offset\n");
        return 0;
    }
    if (goid == 0) {
        bpf_printk("runtime.newproc1 | failed to extract goroutine id\n");
        return 0;
    }
    int stack_id = 0;
    if (read_stack_id(ctx, &stack_id)) {
        bpf_printk("runtime.newproc1 | failed to read stack id\n");
        return 0;
    }
    struct newproc1_event_key key = {
        .goroutine_id = goid,
        .ktime = bpf_ktime_get_ns(),
    };
    struct newproc1_event event = {
        .stack_id = stack_id,
    };
    bpf_map_update_elem(&newproc1_events, &key, &event, BPF_ANY);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
