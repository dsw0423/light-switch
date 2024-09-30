#include <inttypes.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_errno.h>
#include <rte_malloc.h>
#include <stdint.h>

#include "main.h"
#include "arp.h"
#include "icmp.h"
#include "ipv4.h"

static void
process_packet(struct rte_mbuf *m) {
    struct rte_ether_hdr *ether = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    uint16_t ether_type;

    ether_type = rte_be_to_cpu_16(ether->ether_type);
    switch (ether_type) {
    case RTE_ETHER_TYPE_ARP:
        process_arp(m);
        break;
    case RTE_ETHER_TYPE_IPV4:
        process_ipv4(m);
        break;
    default:
        rte_pktmbuf_free(m);
        break;
    }
}

void
packet_processor_loop() {
    uint16_t nb_pkts;
    struct rte_mbuf *mbufs[16];

    while (1) {
        nb_pkts = rte_ring_dequeue_burst(app.packet_dispatcher_processor_ring, mbufs, 16, NULL);
        for (uint16_t i = 0; i < nb_pkts; ++i)
            process_packet(mbufs[i]);
    }
}
