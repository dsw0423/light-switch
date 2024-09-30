#include "ethernet.h"
#include "main.h"

#include <rte_ether.h>

void
l2_send(struct rte_mbuf *m, struct rte_ether_addr *dst, struct rte_ether_addr *src, uint16_t eth_type) {
    struct rte_ether_hdr *ether = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

    ether->dst_addr = *dst;
    ether->src_addr = *src;
    ether->ether_type = rte_cpu_to_be_16(eth_type);
}

void
l2_reply(struct rte_mbuf *m) {
    struct rte_ether_hdr *ether = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

    ether->dst_addr = ether->src_addr;
    ether->src_addr = app.ports_addr[m->port];
}
