#include "icmp.h"
#include "main.h"
#include "ipv4.h"

#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_icmp.h>

void
process_icmp(struct rte_mbuf *m) {
    struct rte_icmp_hdr *icmp =
        rte_pktmbuf_mtod_offset(m, struct rte_icmp_hdr *,
            sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));

    switch (icmp->icmp_type) {
        case RTE_IP_ICMP_ECHO_REQUEST:
            if (icmp->icmp_code == 0) {
                icmp_echo_reply(m);
                goto send_to_tx_dispatcher;
            } else
                rte_pktmbuf_free(m);
            return;
        default:
            rte_pktmbuf_free(m);
            return;
    }

send_to_tx_dispatcher:
    while (rte_ring_enqueue(app.processor_tx_dispatcher_ring, m) != 0)
        continue;
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

static inline void
icmp_echo_reply(struct rte_mbuf *m) {
    struct rte_ipv4_hdr *ipv4 = rte_pktmbuf_mtod_offset(m, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
    struct rte_icmp_hdr *icmp = (struct rte_icmp_hdr *)(ipv4 + 1);

    ipv4_reply(m);

    icmp->icmp_type = RTE_IP_ICMP_ECHO_REPLY;
    icmp->icmp_cksum = 0;
    icmp->icmp_cksum =
        icmp_checksum(icmp, rte_be_to_cpu_16(ipv4->total_length) - rte_ipv4_hdr_len(ipv4));
}
