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
#include "ethernet.h"

static void
arp_reply(struct rte_mbuf *m) {
    struct rte_ether_hdr *ether = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    struct rte_arp_hdr *arp = (struct rte_arp_hdr *)(ether + 1);

    arp->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REPLY);
    arp->arp_data.arp_tip = arp->arp_data.arp_sip;
    arp->arp_data.arp_tha = arp->arp_data.arp_sha;
    arp->arp_data.arp_sip = rte_cpu_to_be_32(app.switch_ipv4_addr);
    arp->arp_data.arp_sha = app.ports_addr[m->port];

    l2_reply(m);
}

void
process_arp(struct rte_mbuf *m) {
    struct rte_ether_hdr *ether = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    struct rte_arp_hdr *arp = (struct rte_arp_hdr *)(ether + 1);

    if (arp->arp_data.arp_tip == rte_cpu_to_be_32(app.switch_ipv4_addr)) {
        if (arp->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REQUEST)) {
            arp_reply(m);
            rte_ring_enqueue(app.processor_tx_dispatcher_ring, m);
        } else {
            rte_pktmbuf_free(m);
        }
    } else {
        rte_ring_enqueue(app.processor_tx_dispatcher_ring, m);
    }
}
