#include "udp.h"
#include "dhcp.h"

#include <inttypes.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <stdint.h>

struct rte_mbuf *
process_udp(struct rte_mbuf *m, uint16_t port) {
    struct rte_udp_hdr *udp = 
        rte_pktmbuf_mtod_offset(m, struct rte_udp_hdr *,
            sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));

    struct rte_mbuf *m_local = NULL;
    uint16_t len;

    switch (rte_be_to_cpu_16(udp->dst_port)) {
        /* DHCP */
        case 67:
            m_local = process_dhcp(m, port, &len);
            break;
        default:
            break;
    }

    if (m_local) {
        printf("processing UDP\n");
        fflush(stdout);
        udp = rte_pktmbuf_mtod_offset(m_local, struct rte_udp_hdr *,
            sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));

        struct rte_ipv4_hdr *ipv4 = 
            rte_pktmbuf_mtod_offset(m_local, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));

        udp->dgram_len = rte_cpu_to_be_16(len + sizeof(*udp));
        uint16_t udp_port = udp->src_port;
        udp->src_port = udp->dst_port;
        udp->dst_port = udp_port;
    }

    return m_local;
}