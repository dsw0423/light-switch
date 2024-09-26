#include <inttypes.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <stdint.h>
#include <rte_malloc.h>

#include "dhcp.h"

static inline
uint8_t *skip_dhcp_magic_number(uint8_t *data) {
    if(data[0] == 99 && data[1] == 130 && data[2] == 83 && data[3] == 99) {
        printf("has magic number\n");
        fflush(stdout);
        return data + 4;
    }
    printf("no magic number\n");
    fflush(stdout);
    return data;
}

static inline
uint8_t *next_option(uint8_t *option) {
    uint8_t len;

    option += 1;
    len = *option++;
    option += len;

    return option;
}

static
uint32_t dhcp_offer(uint8_t *data) {
    uint8_t *begin = data;
    uint32_t ip;

    /* message type: DHCP offer */
    *data++ = DHCP_OPT_MESSAGE_TYPE;
    *data++ = 1;
    *data++ = DHCP_OPT_MESSAGE_TYPE_OFFER;

    /* DHCP server identifier */
    *data++ =  DHCP_OPT_IDENTIFIER;
    *data++ = 4;
    ip = RTE_IPV4(10,0,0,1);
    *(uint32_t *)data = rte_cpu_to_be_32(ip);
    data += 4;

    /* IP address lease */
    *data++ = DHCP_OPT_IP_ADDR_LEASE;
    *data++ = 4;
    *(uint32_t *)data = rte_cpu_to_be_32(60 * 60);
    data += 4;

    /* renewal time */
    *data++ = DHCP_OPT_RENEWAL_TIME;
    *data++ = 4;
    *(uint32_t *)data = rte_cpu_to_be_32(60 * 60 / 2);
    data += 4;

    /* rebinding time */
    *data++ = DHCP_OPT_REBIND_TIME;
    *data++ = 4;
    *(uint32_t *)data = rte_cpu_to_be_32(60 * 60 / 2);
    data += 4;

    /* subnet mask */
    *data++ = DHCP_OPT_SUBNET_MASK;
    *data++ = 4;
    ip = RTE_IPV4(255,255,255,0);
    *(uint32_t *)data = rte_cpu_to_be_32(ip);
    data += 4;

    /* broadcast address */
    *data++ = DHCP_OPT_BROADCAST_ADDR;
    *data++ = 4;
    ip = RTE_IPV4(10,0,0,255);
    *(uint32_t *)data = rte_cpu_to_be_32(ip);
    data += 4;

    /* router */
    *data++ = DHCP_OPT_ROUTER;
    *data++ = 4;
    ip = RTE_IPV4(10,0,0,1);
    *(uint32_t *)data = rte_cpu_to_be_32(ip);
    data += 4;

    /* domain name */
    *data++= DHCP_OPT_DOMAIN_NAME;
    *data++ = sizeof(DOMAIN_NAME) - 1;
    rte_memcpy(data, DOMAIN_NAME, sizeof(DOMAIN_NAME) - 1);
    data += sizeof(DOMAIN_NAME) - 1;

    /* DNS */
    *data++ = DHCP_OPT_DNS;
    *data++ = 4;
    ip = RTE_IPV4(10,0,0,1);
    *(uint32_t *)data = rte_cpu_to_be_32(ip);
    data += 4;

    /* END */
    *data++ = DHCP_OPT_END;

    return data - begin;
}

static
uint32_t dhcp_ack(uint8_t *data) {
    uint32_t ret = dhcp_offer(data);
    data += 2;
    *data = DHCP_OPT_MESSAGE_TYPE_ACK;
    return ret;
}

struct rte_mbuf *process_dhcp(struct rte_mbuf *m, uint16_t port, uint16_t *len) {
    static uint8_t free_host_number = 10;
    uint64_t pre_len = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr);
    struct dhcp_hdr *dhcp = rte_pktmbuf_mtod_offset(m, struct dhcp_hdr *, pre_len);
    uint8_t *option_origin = (uint8_t *)dhcp + sizeof(struct dhcp_hdr);
    uint8_t *option;
    uint32_t options_len;

    printf("segs = %d\n", m->nb_segs);
    printf("pkt len = %d\n", m->pkt_len);
    printf("data len = %d\n", m->data_len);
    fflush(stdout);

    if (dhcp->op == DHCP_OP_REQUEST) {
        option = skip_dhcp_magic_number(option_origin);
        while (*option != DHCP_OPT_END) {
            if (*option == DHCP_OPT_MESSAGE_TYPE) {
                printf("message type\n");
                fflush(stdout);
                option += 2;
                switch (*option) {
                    /* response DHCP discover */
                    case DHCP_OPT_MESSAGE_TYPE_DISCOVER:
                        printf("discover\n");
                        fflush(stdout);
                        options_len = dhcp_offer(skip_dhcp_magic_number(option_origin));
                        dhcp->op = DHCP_OP_REPLY;
                        dhcp->yiaddr = rte_cpu_to_be_32(RTE_IPV4(10,0,0,free_host_number));
                        dhcp->siaddr = rte_cpu_to_be_32(RTE_IPV4(10,0,0,1));
                        m->pkt_len = m->data_len = (uint32_t)pre_len + (uint32_t)sizeof(struct dhcp_hdr) + 4 + options_len;
                        *len = (uint32_t)sizeof(struct dhcp_hdr) + 4 + options_len;
                        printf("pkt offer len = %d\n", m->pkt_len);
                        printf("DHCP header + data len = %d\n", *len);
                        fflush(stdout);
                        break;
                    /* TODO: support lease renew. */
                    case DHCP_OPT_MESSAGE_TYPE_REQUEST:
                        printf("request\n");
                        fflush(stdout);
                        options_len = dhcp_ack(skip_dhcp_magic_number(option_origin));
                        dhcp->op = DHCP_OP_REPLY;
                        dhcp->yiaddr = rte_cpu_to_be_32(RTE_IPV4(10,0,0,free_host_number++));
                        dhcp->siaddr = rte_cpu_to_be_32(RTE_IPV4(10,0,0,1));
                        m->pkt_len = m->data_len = (uint32_t)pre_len + (uint32_t)sizeof(struct dhcp_hdr) + 4 + options_len;
                        *len = (uint32_t)sizeof(struct dhcp_hdr) + 4 + options_len;
                        printf("pkt ack len = %d\n", m->pkt_len);
                        printf("DHCP header + data len = %d\n", *len);
                        fflush(stdout);
                        break;
                    default:
                        printf("goto free\n");
                        fflush(stdout);
                        goto free_pkt;
                        break;
                }

                /* no need to look up other options. */
                break;
            } else {
                option = next_option(option);
            }
        }

        if (*option != DHCP_OPT_END) {
            printf("finished DHCP processing\n");
            fflush(stdout);
            return m;
        }
        printf("not found message type option\n");
        fflush(stdout);
    }
    printf("not DHCP request\n");
    fflush(stdout);

free_pkt:
    rte_pktmbuf_free(m);
    printf("free packet\n");
    fflush(stdout);
    return NULL;
}
