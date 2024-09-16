#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

struct stack_t {
    uintptr_t lo;
    uintptr_t hi;
};

struct gobuf_t {
    uintptr_t sp;
    uintptr_t pc;
    uintptr_t g;
    uintptr_t ctxt;
    uintptr_t ret;
    uintptr_t lr;
    uintptr_t bp;
};

// https://github.com/golang/go/blob/release-branch.go1.23/src/runtime/runtime2.go#L458
struct g_t {
    struct stack_t stack_instance;
    uintptr_t stackguard0;
    uintptr_t stackguard1;
    uintptr_t _panic;
    uintptr_t _defer;
    uintptr_t m;
    struct gobuf_t sched;
    uintptr_t syscallsp;
    uintptr_t syscallpc;
    uintptr_t syscallbp;
    uintptr_t stktopsp;
    uintptr_t param;
    uint32_t atomicstatus;
    uint32_t stackLock;
    int64_t goid;
};

// read_goroutine_id reads the goroutine id from the task_struct.
// 1 on failure.
static __always_inline int read_goroutine_id(struct task_struct *task, int64_t *goroutine_id) {
    void *base;
    BPF_CORE_READ_INTO(&base, &(task->thread), fsbase);
    if (base == NULL) {
        return 1;
    }

    // https://www.usenix.org/conference/srecon23apac/presentation/liang
    uintptr_t g_addr = 0;
    if (bpf_core_read_user(&g_addr, sizeof(uintptr_t), base - 8)) {
        return 1;
    }

    struct g_t g;
    if (bpf_core_read_user(&g, sizeof(struct g_t), (void *)g_addr)) {
        return 1;
    }
    *goroutine_id = g.goid;

    // TODO: Why is this happening? We may be able to ignore this.
    // The Go runtime manages goroutines, and developers generally don't need to interact with
    // goroutine IDs directly. In fact, the language specification does not provide a built-in way
    // to obtain a goroutine's ID, as the designers of Go intended to keep goroutines abstracted
    // away from such details.
    if (*goroutine_id == 0) {
        return 1;
    }

    return 0;
}
