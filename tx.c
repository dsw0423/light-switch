#include <inttypes.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <stdint.h>

#include "main.h"

extern struct rte_mempool *mbuf_pool;

extern struct rte_ring *packet_dispatcher_tx_dispatcher_ring;
extern struct rte_ring *processor_tx_dispatcher_ring;
extern struct rte_ring **tx_rings_table;

extern struct mac_port_entry *mac_port_table;
extern volatile uint16_t nb_mac_port_entries;

static inline void
send_to_port(const struct rte_mbuf **mbufs, uint16_t nb_bufs, uint16_t portid) {
    uint16_t nb_tx;

    nb_tx = rte_eth_tx_burst(portid, 0, mbufs, nb_bufs);

    /* simply drop the unsent packets. */
    for (uint16_t i = nb_tx; i < nb_bufs; ++i)
        rte_pktmbuf_free(mbufs[i]);
}

void
tx_all_ports_loop() {
    struct rte_ring *tx_ring;
    uint16_t nb_pkts;
    struct rte_mbuf *mbufs[16];

    while (1) {
        for (uint16_t port = 0; port < app.nb_ports; ++port) {
            tx_ring = tx_rings_table[port];
            nb_pkts = rte_ring_dequeue_burst(tx_ring, mbufs, 16, NULL);
            send_to_port(mbufs, nb_pkts, port);
        }
    }
}

static inline uint16_t
get_dst_port(const struct rte_mbuf *m) {
    struct rte_ether_hdr *ether = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

    for (uint16_t i = 0; i < nb_mac_port_entries; ++i) {
        if (ether_addr_is_same(&mac_port_table[i].addr, &ether->dst_addr))
            return mac_port_table[i].port;
    }

    return -1;
}

static void
dispatch_pkts_to_tx_ring(const struct rte_mbuf **mbufs, uint16_t nb_pkts) {
    uint16_t portid;
    struct rte_ring *tx_ring;
    struct rte_mbuf *m_cloned;

    for (uint16_t i = 0; i < nb_pkts; ++i) {
        portid = get_dst_port(mbufs[i]);
        if (portid >= 0) {
            tx_ring = tx_rings_table[portid];
            rte_ring_enqueue(tx_ring, mbufs[i]);
        } else {
            /* flooding */
            for (uint16_t port = 0; port < app.nb_ports; ++port) {
                if (port != mbufs[i]->port) {
                    m_cloned = rte_pktmbuf_clone(mbufs[i], mbuf_pool);
                    rte_ring_enqueue(tx_rings_table[port], m_cloned);
                }
            }
            rte_pktmbuf_free(mbufs[i]);
        }
    }
}

void
tx_dispatcher_loop() {
    struct rte_mbuf *mbufs[16];
    uint16_t nb_pkts;

    while (1) {
        /* dispatch packet_dispatcher ring. */
        nb_pkts = rte_ring_dequeue_burst(packet_dispatcher_tx_dispatcher_ring, mbufs, 16, NULL);
        dispatch_pkts_to_tx_ring(mbufs, nb_pkts);

        /* dispatch processor ring. */
        nb_pkts = rte_ring_dequeue_burst(processor_tx_dispatcher_ring, mbufs, 16, NULL);
        dispatch_pkts_to_tx_ring(mbufs, nb_pkts);
    }
}
