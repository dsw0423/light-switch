#include <inttypes.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_errno.h>
#include <rte_malloc.h>
#include <stdint.h>

#include "udp.h"
#include "main.h"

struct app_context app;

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

#define SWITCH_IP_ADDR  RTE_IPV4(10, 0, 0, 1)

static struct rte_ether_addr ports_addr[RTE_MAX_ETHPORTS];
static const struct rte_ether_addr broad_cast_macaddr = {
    .addr_bytes = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
};

static inline int
port_init(uint16_t port, struct rte_mempool *mbuf_pool) {
    struct rte_eth_conf port_conf;
    const uint16_t rx_rings = 1, tx_rings = 1;
    uint16_t nb_rxd = RX_RING_SIZE;
    uint16_t nb_txd = TX_RING_SIZE;
    int retval;
    uint16_t q;
    struct rte_eth_dev_info dev_info;
    struct rte_eth_txconf txconf;

    if (!rte_eth_dev_is_valid_port(port))
        return -1;

    memset(&port_conf, 0, sizeof(struct rte_eth_conf));

    retval = rte_eth_dev_info_get(port, &dev_info);
    if (retval != 0) {
        printf("Error during getting device (port %u) info: %s\n", port,
               strerror(-retval));
        return retval;
    }

    if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
        port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

    /* Configure the Ethernet device. */
    retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
    if (retval != 0)
        return retval;

    retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
    if (retval != 0)
        return retval;

    /* Allocate and set up 1 RX queue per Ethernet port. */
    for (q = 0; q < rx_rings; q++) {
        retval = rte_eth_rx_queue_setup(
            port, q, nb_rxd, rte_eth_dev_socket_id(port), NULL, mbuf_pool);
        if (retval < 0)
            return retval;
    }

    txconf = dev_info.default_txconf;
    txconf.offloads = port_conf.txmode.offloads;
    /* Allocate and set up 1 TX queue per Ethernet port. */
    for (q = 0; q < tx_rings; q++) {
        retval = rte_eth_tx_queue_setup(port, q, nb_txd,
                                        rte_eth_dev_socket_id(port), &txconf);
        if (retval < 0)
            return retval;
    }

    /* Starting Ethernet port. 8< */
    retval = rte_eth_dev_start(port);
    /* >8 End of starting of ethernet port. */
    if (retval < 0)
        return retval;

    /* Display the port MAC address. */
    struct rte_ether_addr addr;
    retval = rte_eth_macaddr_get(port, &addr);
    if (retval != 0)
        return retval;

    printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8 " %02" PRIx8
           " %02" PRIx8 " %02" PRIx8 "\n",
           port, RTE_ETHER_ADDR_BYTES(&addr));

    /* Enable RX in promiscuous mode for the Ethernet device. */
    retval = rte_eth_promiscuous_enable(port);
    /* End of setting RX port in promiscuous mode. */
    if (retval != 0)
        return retval;

    return 0;
}

static void
mac_flooding(struct rte_mbuf *m) {
    printf("flooding\n");
    fflush(stdout);

    for (int p = 0; p < app.nb_ports; ++p) {
        if (p != m->port) {
            struct rte_mbuf *m_cloned = rte_pktmbuf_clone(m, app.mbuf_pool);
            if (m_cloned) {
                const uint16_t nb_tx = rte_eth_tx_burst(p, 0, &m_cloned, 1);
                if (unlikely(nb_tx != 1))
                    rte_pktmbuf_free(m_cloned);
            }
        }
    }
    rte_pktmbuf_free(m);
}

static void
forward_out(struct rte_mbuf *m) {
    struct rte_ether_hdr *ether = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    uint16_t i;

    for (i = 0; i < app.nb_mac_port_entries; ++i) {
        if (ether_addr_is_same(&ether->dst_addr, &app.mac_port_table[i].addr)) {
            printf("forwarding\n");
            fflush(stdout);

            const uint16_t nb_tx = rte_eth_tx_burst(app.mac_port_table[i].port, 0, &m, 1);
            if (unlikely(nb_tx != 1))
                rte_pktmbuf_free(m);
            break;
        }
    }

    if (i == app.nb_mac_port_entries) {
        mac_flooding(m);
    }
}

static void
process_arp(struct rte_mbuf *m, uint16_t port) {
    struct rte_ether_hdr *ether = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    struct rte_arp_hdr *arp = (struct rte_arp_hdr *)(ether + 1);

    if (arp->arp_data.arp_tip == rte_cpu_to_be_32(SWITCH_IP_ADDR)) {
        if (arp->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REQUEST)) {
            arp->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REPLY);
            arp->arp_data.arp_tip = arp->arp_data.arp_sip;
            arp->arp_data.arp_tha = arp->arp_data.arp_sha;
            arp->arp_data.arp_sip = rte_cpu_to_be_32(SWITCH_IP_ADDR);
            rte_eth_macaddr_get(port, &arp->arp_data.arp_sha);
        } else {
            rte_pktmbuf_free(m);
            m = NULL;
        }

        if (m) {
            ether->dst_addr = ether->src_addr;
            rte_eth_macaddr_get(port, &ether->src_addr);
            const uint16_t nb_tx = rte_eth_tx_burst(port, 0, &m, 1);
            if (unlikely(nb_tx != 1))
                rte_pktmbuf_free(m);
        }
    } else {
        mac_flooding(m);
    }
}

static int
is_send_to_switch(struct rte_ether_addr *dst_addr) {
    for (int i = 0; i < app.nb_ports; ++i) {
        if (ether_addr_is_same(&ports_addr[i], dst_addr))
            return 1;
    }
    return 0;
}

static uint16_t
icmp_checksum(void *addr, int count) {
    register uint32_t sum = 0;
    uint16_t temp = *(uint16_t *)addr;

    while (count > 1) {
        // sum += *(unsigned short*)addr++;
        sum += temp;
        addr = (char *)addr + 2;
        count -= 2;
        temp = *(uint16_t *)addr;
    }

    if (count > 0) {
        sum += *(uint8_t *)addr;
    }

    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    return ~sum;
}

static void
process_ipv4(struct rte_mbuf *m, uint16_t port) {
    struct rte_ether_hdr *ether = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    struct rte_ipv4_hdr *ipv4 = (struct rte_ipv4_hdr *)(ether + 1);
    struct rte_icmp_hdr *icmp = (struct rte_icmp_hdr *)(ipv4 + 1);
    uint8_t proto = ipv4->next_proto_id;

    if (likely(!ether_addr_is_same(&ether->dst_addr, &broad_cast_macaddr))) {
        /* process ICMPv4 request. */
        if (proto == 1 && icmp->icmp_type == RTE_IP_ICMP_ECHO_REQUEST &&
            icmp->icmp_code == 0) {
            printf("processing ICMP\n");
            fflush(stdout);
            ipv4->time_to_live--;

            uint32_t tmp_ip = ipv4->dst_addr;
            ipv4->dst_addr = ipv4->src_addr;
            ipv4->src_addr = tmp_ip;

            struct rte_ether_addr tmp_mac = ether->dst_addr;
            ether->dst_addr = ether->src_addr;
            ether->src_addr = tmp_mac;

            ipv4->hdr_checksum = 0;
            ipv4->hdr_checksum = rte_ipv4_cksum(ipv4);

            icmp->icmp_type = RTE_IP_ICMP_ECHO_REPLY;
            icmp->icmp_cksum = 0;
            icmp->icmp_cksum =
                icmp_checksum(icmp, rte_be_to_cpu_16(ipv4->total_length) -
                                        rte_ipv4_hdr_len(ipv4));

            const uint16_t nb_tx = rte_eth_tx_burst(port, 0, &m, 1);
            if (unlikely(nb_tx != 1))
                rte_pktmbuf_free(m);
            return;
        }
    }

    /* process DHCP request. */
    if (proto == 17) {
        struct rte_mbuf *m_local = process_udp(m, port);
        if (m_local) {
            printf("sending packet\n\n");
            fflush(stdout);
            ether = rte_pktmbuf_mtod(m_local, struct rte_ether_hdr *);
            ipv4 = (struct rte_ipv4_hdr *)(ether + 1);

            ipv4->time_to_live--;
            ipv4->src_addr = rte_cpu_to_be_32(RTE_IPV4(10, 0, 0, 1));
            ipv4->dst_addr = rte_cpu_to_be_32(RTE_IPV4(10, 0, 0, 10));
            ipv4->total_length =
                rte_cpu_to_be_16(m_local->pkt_len - sizeof(*ether));

            struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(ipv4 + 1);
            udp->dgram_cksum = 0;
            udp->dgram_cksum = rte_ipv4_udptcp_cksum(ipv4, udp);

            ipv4->hdr_checksum = 0;
            ipv4->hdr_checksum = rte_ipv4_cksum(ipv4);

            ether->dst_addr = ether->src_addr;
            rte_eth_macaddr_get(port, &ether->src_addr);

            const uint16_t nb_tx = rte_eth_tx_burst(port, 0, &m_local, 1);
            if (unlikely(nb_tx != 1)) {
                rte_pktmbuf_free(m_local);
                printf("send failed\n");
                fflush(stdout);
            }
        }
        return;
    }

    forward_out(m);
}

static void
process_pkt(struct rte_mbuf *m, uint16_t port) {
    struct rte_ether_hdr *ether = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    uint16_t ether_type;
    struct rte_mbuf *m_local;

    ether_type = rte_be_to_cpu_16(ether->ether_type);
    switch (ether_type) {
    case RTE_ETHER_TYPE_ARP:
        process_arp(m, port);
        break;
    case RTE_ETHER_TYPE_IPV4:
        process_ipv4(m, port);
        break;
    default:
        rte_pktmbuf_free(m);
        break;
    }
}

static __rte_noreturn int
loop(void *dummy) {
    uint16_t port;

    /*
     * Check that the port is on the same NUMA node as the polling thread
     * for best performance.
     */
    RTE_ETH_FOREACH_DEV(port)
    if (rte_eth_dev_socket_id(port) >= 0 &&
        rte_eth_dev_socket_id(port) != (int)rte_socket_id())
        printf("WARNING, port %u is on remote NUMA node to "
               "polling thread.\n\tPerformance will "
               "not be optimal.\n",
               port);

    printf("\nCore %u forwarding packets. [Ctrl+C to quit]\n", rte_lcore_id());

    for (;;) {
        RTE_ETH_FOREACH_DEV(port) {

            /* Get burst of RX packets, from first port of pair. */
            struct rte_mbuf *bufs[BURST_SIZE];
            const uint16_t nb_rx = rte_eth_rx_burst(port, 0, bufs, BURST_SIZE);
            struct rte_ether_addr port_macaddr;

            rte_eth_macaddr_get(port, &port_macaddr);

            if (unlikely(nb_rx == 0))
                continue;

            for (int i = 0; i < nb_rx; ++i) {
                struct rte_mbuf *m = bufs[i];
                struct rte_ether_hdr *ether =
                    rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

                /* update mac_port_table */
                uint16_t i;
                for (i = 0; i < app.nb_mac_port_entries; ++i) {
                    if (ether_addr_is_same(&app.mac_port_table[i].addr, &ether->src_addr)) {
                        app.mac_port_table[i].port = port;
                        break;
                    }
                }

                /* insert a new entry */
                if (i == app.nb_mac_port_entries) {
                    struct mac_port_entry entry = {
                        .addr = ether->src_addr,
                        .port = port
                    };

                    /* simply reset the table if table is full. */
                    if (app.nb_mac_port_entries == MAC_PORT_TABLE_CAPACITY)
                        app.nb_mac_port_entries = 0;

                    app.mac_port_table[app.nb_mac_port_entries++] = entry;
                }

                if (is_send_to_switch(&ether->dst_addr) ||
                    ether_addr_is_same(&ether->dst_addr, &broad_cast_macaddr))
                    process_pkt(m, port);
                else {
                    forward_out(m);
                }
            }
        }
    }
}

int
main(int argc, char *argv[]) {
    uint16_t portid;

    int ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

    argc -= ret;
    argv += ret;

    /* Check that there is an even number of ports to send/receive on. */
    app.nb_ports = rte_eth_dev_count_avail();
    if (app.nb_ports < 2 || (app.nb_ports & 1))
        rte_exit(EXIT_FAILURE, "Error: number of ports must be even\n");

    /* Allocates mempool to hold the mbufs. 8< */
    app.mbuf_pool = rte_pktmbuf_pool_create(
        "MBUF_POOL", NUM_MBUFS * app.nb_ports, MBUF_CACHE_SIZE, 0,
        RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

    if (app.mbuf_pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

    /* Initializing all ports. 8< */
    RTE_ETH_FOREACH_DEV(portid) {
        if (port_init(portid, app.mbuf_pool) != 0)
            rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n", portid);
        rte_eth_macaddr_get(portid, &ports_addr[portid]);
    }

    app.rx_packet_dispatcher_ring =
        rte_ring_create("rx_dispatcher",
                        1024,
                        rte_socket_id(),
                        RING_F_SP_ENQ | RING_F_SC_DEQ);
    
    if (app.rx_packet_dispatcher_ring == NULL)
        rte_exit(rte_errno, "rte_ring_create(): %s\n" , rte_strerror(rte_errno));

    app.packet_dispatcher_processor_ring =
        rte_ring_create("dispatcher_processor",
                        1024,
                        rte_socket_id(),
                        RING_F_SP_ENQ | RING_F_SC_DEQ);

    if (app.packet_dispatcher_processor_ring == NULL)
        rte_exit(rte_errno, "rte_ring_create(): %s\n", rte_strerror(rte_errno));

    app.packet_dispatcher_tx_dispatcher_ring =
        rte_ring_create("dispatcher_tx_dispatcher",
                        1024,
                        rte_socket_id(),
                        RING_F_SP_ENQ | RING_F_SC_DEQ);

    if (app.packet_dispatcher_tx_dispatcher_ring == NULL)
        rte_exit(rte_errno, "rte_ring_create(): %s\n", rte_strerror(rte_errno));
    
    app.processor_tx_dispatcher_ring =
        rte_ring_create("processor_tx_dispatcher",
                        1024,
                        rte_socket_id(),
                        RING_F_SP_ENQ | RING_F_SC_DEQ);

    if (app.processor_tx_dispatcher_ring == NULL)
        rte_exit(rte_errno, "rte_ring_create(): %s\n", rte_strerror(rte_errno));

    app.tx_rings_table = rte_malloc(NULL, sizeof(struct rte_ring *) * app.nb_ports , 0);
    if (app.tx_rings_table == NULL)
        rte_exit(EXIT_FAILURE, "rte_malloc() failed\n");
    
    for (int i = 0; i < app.nb_ports; ++i) {
        char name[20];
        snprintf(name, sizeof(name), "tx_ring%d", i);
        app.tx_rings_table[i] = rte_ring_create(name, 1024, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
        if (app.tx_rings_table[i] == NULL)
            rte_exit(rte_errno, "rte_ring_create(): %s\n", rte_strerror(rte_errno));
    }

    if (rte_lcore_count() > 1)
        printf("\nWARNING: Too many lcores enabled. Only 1 used.\n");

    loop(NULL);

    rte_eal_cleanup();
    return 0;
}
