// SPDX-License-Identifier: (MIT OR GPL-2.0)
//
// Kernel-side signal collection for healerd.
//
//   tracepoint/oom/mark_victim         -> OOM kills
//   tracepoint/signal/signal_generate  -> crash signals (SEGV, ABRT, BUS, FPE, ILL, KILL)
//   tracepoint/sched/sched_process_exit-> exits of watched processes (filtered in kernel)
//   kprobe/tcp_retransmit_skb          -> TCP retransmits, aggregated per destination
//
// Discrete events go through a ring buffer. Retransmits are high-volume, so
// they are counted in an LRU hash and user space polls the deltas.

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16
#define AF_INET 2

enum event_kind {
	EV_OOM_KILL = 1,
	EV_CRASH_SIGNAL = 2,
	EV_PROCESS_EXIT = 3,
};

struct event {
	__u64 ts_ns;
	__u32 kind;
	__u32 pid;
	__s32 sig;
	__s32 exit_code; // raw task->exit_code for EV_PROCESS_EXIT
	__u8 comm[TASK_COMM_LEN];
};

struct comm_key {
	__u8 comm[TASK_COMM_LEN];
};

struct conn_key {
	__u32 daddr; // network byte order
	__u16 dport; // network byte order
	__u16 pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct comm_key);
	__type(value, __u8);
	__uint(max_entries, 256);
} watched_comms SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct conn_key);
	__type(value, __u64);
	__uint(max_entries, 8192);
} retrans SEC(".maps");

// Only used through a ring buffer pointer; this keeps it in BTF for bpf2go.
const struct event *unused_event __attribute__((unused));

// Tracepoint record layouts (stable ABI; see /sys/kernel/tracing/events/*/format).
struct tp_common {
	__u16 type;
	__u8 flags;
	__u8 preempt_count;
	__s32 pid;
};

struct tp_mark_victim {
	struct tp_common common;
	__s32 pid;
};

struct tp_signal_generate {
	struct tp_common common;
	__s32 sig;
	__s32 errno_;
	__s32 code;
	char comm[TASK_COMM_LEN];
	__s32 pid;
};

// Kernel structs read with CO-RE; offsets are relocated against the running
// kernel's BTF at load time, so no kernel headers are needed.
struct sock_common {
	unsigned short skc_family;
	__u32 skc_daddr;
	__u16 skc_dport;
} __attribute__((preserve_access_index));

struct sock {
	struct sock_common __sk_common;
} __attribute__((preserve_access_index));

struct task_struct {
	int exit_code;
} __attribute__((preserve_access_index));

static __always_inline struct event *reserve(__u32 kind)
{
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return NULL;
	e->ts_ns = bpf_ktime_get_ns();
	e->kind = kind;
	e->pid = 0;
	e->sig = 0;
	e->exit_code = 0;
	__builtin_memset(e->comm, 0, sizeof(e->comm));
	return e;
}

SEC("tracepoint/oom/mark_victim")
int handle_oom_victim(struct tp_mark_victim *ctx)
{
	struct event *e = reserve(EV_OOM_KILL);
	if (!e)
		return 0;
	e->pid = ctx->pid;
	e->sig = 9;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

static __always_inline int is_crash_signal(int sig)
{
	switch (sig) {
	case 4:  // SIGILL
	case 6:  // SIGABRT
	case 7:  // SIGBUS
	case 8:  // SIGFPE
	case 9:  // SIGKILL
	case 11: // SIGSEGV
		return 1;
	}
	return 0;
}

SEC("tracepoint/signal/signal_generate")
int handle_signal_generate(struct tp_signal_generate *ctx)
{
	int sig = ctx->sig;
	if (!is_crash_signal(sig))
		return 0;

	struct event *e = reserve(EV_CRASH_SIGNAL);
	if (!e)
		return 0;
	e->pid = ctx->pid;
	e->sig = sig;
	bpf_probe_read_kernel(e->comm, sizeof(e->comm), ctx->comm);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int handle_process_exit(void *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	__u32 tgid = id >> 32;
	__u32 tid = (__u32)id;
	struct comm_key key = {};

	if (tgid != tid)
		return 0; // a thread, not the whole process

	bpf_get_current_comm(key.comm, sizeof(key.comm));
	if (!bpf_map_lookup_elem(&watched_comms, &key))
		return 0;

	struct event *e = reserve(EV_PROCESS_EXIT);
	if (!e)
		return 0;
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	e->pid = tgid;
	e->exit_code = BPF_CORE_READ(task, exit_code);
	__builtin_memcpy(e->comm, key.comm, sizeof(e->comm));
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("kprobe/tcp_retransmit_skb")
int BPF_KPROBE(handle_retransmit, struct sock *sk)
{
	struct conn_key key = {};
	__u64 one = 1, *val;

	if (!sk)
		return 0;
	if (BPF_CORE_READ(sk, __sk_common.skc_family) != AF_INET)
		return 0;

	key.daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
	key.dport = BPF_CORE_READ(sk, __sk_common.skc_dport);

	val = bpf_map_lookup_elem(&retrans, &key);
	if (val)
		__sync_fetch_and_add(val, 1);
	else
		bpf_map_update_elem(&retrans, &key, &one, BPF_NOEXIST);
	return 0;
}

char _license[] SEC("license") = "Dual MIT/GPL";
