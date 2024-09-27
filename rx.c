#include <inttypes.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <stdint.h>

#include "main.h"

extern struct rte_ring *rx_dispatcher_ring;

#define RX_MBUF_TABLE_SIZE 1024
static struct rte_mbuf *rx_mbuf_table[RX_MBUF_TABLE_SIZE];

static void
rx_port(uint16_t portid) {
    uint16_t nb_rx;
    uint16_t nb_enque;

    nb_rx = rte_eth_rx_burst(portid, 0, rx_mbuf_table, RX_MBUF_TABLE_SIZE);
    if (nb_rx == 0)
        return;
    
    nb_enque = 0;
    do {
        nb_enque += rte_ring_enqueue_burst(rx_dispatcher_ring, rx_mbuf_table, nb_rx, NULL);
    } while (nb_enque < nb_rx);
}

void
rx_all_ports_loop() {
    for (uint16_t port = 0; port < app.nb_ports; ++port) {
        rx_port(port);
    }
}
