//go:build ignore

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

#define MAX_DNS_PAYLOAD 256
#define TASK_COMM_LEN 16

struct dns_event {
    u32 pid;
    char comm[TASK_COMM_LEN];
    u32 dst_ip;
    u32 payload_len;
    unsigned char payload[MAX_DNS_PAYLOAD];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("fentry/udp_sendmsg")
int BPF_PROG(dns_send, struct sock *sk, struct msghdr *msg, size_t len)
{
    struct dns_event *e;
    u16 dport = 0;

    BPF_CORE_READ_INTO(&dport, sk, __sk_common.skc_dport);
    dport = bpf_ntohs(dport);
    if (dport != 53)
        return 0;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    __builtin_memset(e, 0, sizeof(*e));

    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    BPF_CORE_READ_INTO(&e->dst_ip, sk, __sk_common.skc_daddr);

    // Locate the data buffer in the msghdr
    struct iovec iov_local;
    __builtin_memset(&iov_local, 0, sizeof(iov_local));
    void *data_ptr = NULL;
    size_t data_len = 0;

    BPF_CORE_READ_INTO(&data_len, msg, msg_iter.count);

    if (bpf_core_field_exists(struct iov_iter, __ubuf_iovec)) {
        struct iovec tmp_iov;
        if (bpf_core_read(&tmp_iov, sizeof(tmp_iov), &msg->msg_iter.__ubuf_iovec) == 0) {
            iov_local = tmp_iov;
        }
    }

    // If that didn't work, try reading as if __iov field exists (older kernels)
    if (iov_local.iov_base == NULL) {
        void *iov_ptr = NULL;

        if (bpf_core_field_exists(struct iov_iter, __iov)) {
            bpf_core_read(&iov_ptr, sizeof(iov_ptr), &msg->msg_iter.__iov);
        }

        if (iov_ptr != NULL) {
            if (bpf_probe_read_user(&iov_local, sizeof(iov_local), iov_ptr) < 0) {
                bpf_probe_read_kernel(&iov_local, sizeof(iov_local), iov_ptr);
            }
        }
    }

    // If we still don't have a valid buffer, try using the length we read
    if (iov_local.iov_base == NULL && data_len > 0) {
        goto submit;
    }

    data_ptr = iov_local.iov_base;
    if (iov_local.iov_len > 0 && iov_local.iov_len < data_len) {
        data_len = iov_local.iov_len;
    }

    // read dns request payload
    u32 payload_len = data_len;
    if (payload_len > MAX_DNS_PAYLOAD)
        payload_len = MAX_DNS_PAYLOAD;

    if (payload_len == 0) {
        goto submit;
    }

    e->payload_len = payload_len;

    // defensive read of payload length. try user space, fall back to kernel, clear payload len on failure
    if (bpf_probe_read_user(e->payload, payload_len, data_ptr) < 0) {
        if (bpf_probe_read_kernel(e->payload, payload_len, data_ptr) < 0) {
            e->payload_len = 0;
        }
    }

submit:
    bpf_ringbuf_submit(e, 0);
    return 0;
}
char LICENSE[] SEC("license") = "GPL";