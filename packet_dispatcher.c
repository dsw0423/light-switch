#include <inttypes.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <stdint.h>

#include "main.h"

static const struct rte_ether_addr eth_broadcast_addr = {
    .addr_bytes = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
};

static inline int
is_broadcast(const struct rte_mbuf *m) {
    struct rte_ether_hdr *ether = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

    return ether_addr_is_same(&ether->dst_addr, &eth_broadcast_addr);
}

static inline int
is_send_to_switch(const struct rte_mbuf *m) {
    struct rte_ether_hdr *ether = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

    for (uint16_t port = 0; port < app.nb_ports; ++port) {
        if (ether_addr_is_same(&ether->dst_addr, &app.ports_addr[port]))
            return 1;
    }
    return 0;
}


static void
dispatch_packet(const struct rte_mbuf *m) {
    if (is_send_to_switch(m) || is_broadcast(m)) {
        while (rte_ring_enqueue(app.packet_dispatcher_processor_ring, m) != 0)
            rte_delay_us(10);
    } else {
        while (rte_ring_enqueue(app.packet_dispatcher_tx_dispatcher_ring, m) != 0)
            rte_delay_us(10);
    }
}

void
packet_dispatcher_loop() {
    struct rte_mbuf *mbufs[16];
    unsigned int nb_pkts;

    while (1) {
        nb_pkts = rte_ring_dequeue_burst(app.rx_packet_dispatcher_ring, mbufs, 16, NULL);
        for (uint32_t i = 0; i < nb_pkts; ++i)
            dispatch_packet(mbufs[i]);
    }
}
