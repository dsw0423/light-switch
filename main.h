#ifndef MAIN_H
#define MAIN_H

#include <stdint.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_ether.h>

struct mac_port_entry {
    struct rte_ether_addr addr;
    uint16_t port;
};

#define MAC_PORT_TABLE_CAPACITY 1024

struct app_context {
    uint16_t nb_ports;                                      /* number of ethernet ports. */
    struct rte_mempool *mbuf_pool;                          /* mempool from which mbufs are allocated. */
    struct rte_ring *rx_packet_dispatcher_ring;             /* rx to packet_dispatcher ring. */
    struct rte_ring *packet_dispatcher_processor_ring;      /* packet_dispatcher to processor ring. */
    struct rte_ring *packet_dispatcher_tx_dispatcher_ring;  /* packet_dispatcher to tx_dispatcher ring. */
    struct rte_ring *processor_tx_dispatcher_ring;          /* processor to tx_dispatcher ring.*/
    struct rte_ring **tx_rings_table;                       /* tx rings of all ports. */

    struct mac_port_entry mac_port_table[MAC_PORT_TABLE_CAPACITY];    /* mac forwarding table. */
    volatile uint16_t nb_mac_port_entries;                  /* size of mac_port_table. */
};

/* global context */
extern struct app_context app;

static inline int 
ether_addr_is_same(const struct rte_ether_addr *ea, const struct rte_ether_addr *eb) {
    for (int i = 0; i < RTE_ETHER_ADDR_LEN; ++i)
        if (ea->addr_bytes[i] != eb->addr_bytes[i])
            return 0;

    return 1;
}

#endif