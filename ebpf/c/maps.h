#ifndef __MAPS_H__
#define __MAPS_H__

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>

#define MAX_STACK_ADDRESSES 1024 // max amount of diff stack trace addrs to buffer
#define MAX_STACK_DEPTH 20 // max depth of each stack trace to track

#define BPF_MAP(_name, _type, _key_type, _value_type, _max_entries) \
    struct {                                                        \
        __uint(type, _type);                                        \
        __uint(max_entries, _max_entries);                          \
        __type(key, _key_type);                                     \
        __type(value, _value_type);                                 \
    } _name SEC(".maps");

// stack traces: the value is 1 big byte array of the stack addresses
typedef __u64 stack_trace_t[MAX_STACK_DEPTH];
#define BPF_STACK_TRACE(_name, _max_entries) \
    BPF_MAP(_name, BPF_MAP_TYPE_STACK_TRACE, u32, stack_trace_t, _max_entries)

BPF_STACK_TRACE(stack_addresses, MAX_STACK_ADDRESSES); // store stack traces

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

struct event {
    int64_t goroutine_id;
    int stack_id;
    bool exit;
};

struct event *unused __attribute__((unused));

#endif /* __MAPS_H__ */
