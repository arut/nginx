#include <errno.h>
#include <linux/string.h>
#include <linux/udp.h>
#include <linux/bpf.h>
/*
 * the bpf_helpers.h is not included into linux-headers, only available
 * with kernel sources in "tools/lib/bpf/bpf_helpers.h" or in libbpf.
 */
#include <bpf/bpf_helpers.h>


#if !defined(SEC)
#define SEC(NAME)  __attribute__((section(NAME), used))
#endif


#if defined(LICENSE_GPL)

/*
 * To see debug:
 *
 *  echo 1 > /sys/kernel/debug/tracing/events/bpf_trace/enable
 *  cat /sys/kernel/debug/tracing/trace_pipe
 *  echo 0 > /sys/kernel/debug/tracing/events/bpf_trace/enable
 */

#define debugmsg(fmt, ...)                                                    \
do {                                                                          \
    char __buf[] = fmt;                                                       \
    bpf_trace_printk(__buf, sizeof(__buf), ##__VA_ARGS__);                    \
} while (0)

#else

#define debugmsg(fmt, ...)

#endif

char _license[] SEC("license") = LICENSE;

/*****************************************************************************/

#define NGX_QUIC_PKT_LONG        0x80  /* header form */
#define NGX_QUIC_SERVER_CID_LEN  20


struct bpf_map_def SEC("maps")  ngx_quic_listen;
struct bpf_map_def SEC("maps")  ngx_quic_worker;
struct bpf_map_def SEC("maps")  ngx_quic_nlisten;


SEC(PROGNAME)
int ngx_quic_select_socket_by_dcid(struct sk_reuseport_md *ctx)                                                       \
{
    int             rc, flags;
    __u32           zero, *nsockets, ns;
    size_t          len, offset;
    unsigned char  *start, *end, dcid[NGX_QUIC_SERVER_CID_LEN];

    start = ctx->data;
    end = ctx->data_end;

    offset = sizeof(struct udphdr) + 1; /* UDP header + QUIC flags */
    if (start + offset > end) {
        goto bad_dgram;
    }

    flags = start[offset - 1];
    if (flags & NGX_QUIC_PKT_LONG) {

        offset += 5; /* QUIC version + DCID len */
        if (start + offset > end) {
            goto bad_dgram;
        }

        len = start[offset - 1];
        if (len != NGX_QUIC_SERVER_CID_LEN) {
            goto new_conn;
        }
    }

    if (start + offset + NGX_QUIC_SERVER_CID_LEN > end) {
        goto bad_dgram;
    }

    memcpy(dcid, start + offset, NGX_QUIC_SERVER_CID_LEN);

    rc = bpf_sk_select_reuseport(ctx, &ngx_quic_worker, dcid, 0);

    if (rc == 0) {
        debugmsg("nginx quic socket selected by dcid");
        return SK_PASS;
    }

    if (rc != -ENOENT) {
        debugmsg("nginx quic bpf_sk_select_reuseport() failed:%d", rc);
        return SK_DROP;
    }

new_conn:

    zero = 0;

    nsockets = bpf_map_lookup_elem(&ngx_quic_nlisten, &zero);

    if (nsockets == NULL) {
        debugmsg("nginx quic nsockets undefined");
        return SK_DROP;
    }

    ns = ctx->hash % *nsockets;

    rc = bpf_sk_select_reuseport(ctx, &ngx_quic_listen, &ns, 0);

    if (rc == 0) {
        debugmsg("nginx quic socket selected by hash:%d", (int) ns);
        return SK_PASS;
    }

    if (rc != -ENOENT) {
        debugmsg("nginx quic bpf_sk_select_reuseport() failed:%d", rc);
        return SK_DROP;
    }

    (void) bpf_map_update_elem(&ngx_quic_nlisten, &zero, &ns, BPF_ANY);

    debugmsg("nginx quic cut sockets array:%d", (int) ns);

    return SK_DROP;

bad_dgram:

    debugmsg("nginx quic bad datagram");

    return SK_DROP;
}
