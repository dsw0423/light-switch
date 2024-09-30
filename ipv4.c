#include "icmp.h"
#include "ipv4.h"
#include "ethernet.h"
#include "main.h"

#include <rte_ether.h>
#include <rte_ip.h>

void
process_ipv4(struct rte_mbuf *m) {
    struct rte_ether_hdr *ether = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    struct rte_ipv4_hdr *ipv4 = (struct rte_ipv4_hdr *)(ether + 1);

    switch (ipv4->next_proto_id) {
        case IPV4_PROTO_TYPE_ICMPV4:
            process_icmp(m);
            break;
        default:
            rte_pktmbuf_free(m);
            break;
    }
}

void
ipv4_reply(struct rte_mbuf *m) {
    struct rte_ether_hdr *ether = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    struct rte_ipv4_hdr *ipv4 = (struct rte_ipv4_hdr *)(ether + 1);

    l2_reply(m);

    ipv4->time_to_live--;

    ipv4->dst_addr = ipv4->src_addr;
    ipv4->src_addr = rte_cpu_to_be_32(app.switch_ipv4_addr);

    ipv4->hdr_checksum = 0;
    ipv4->hdr_checksum = rte_ipv4_cksum(ipv4);
}
