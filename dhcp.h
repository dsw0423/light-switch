#ifndef DHCP_H
#define DHCP_H

#include <rte_mbuf.h>
#include <stdint.h>

#define DHCP_SERVER_NAME_LEN        64
#define DHCP_BOOT_FILE_NAME_LEN     128 
#define DHCP_CLIENT_HW_ADDR         16

/* DHCP header fields */
#define DHCP_OP_REQUEST     1
#define DHCP_OP_REPLY       2
#define DHCP_HW_ETHERNET    1

/**
 * DHCP options
 */

/* message type option */
#define DHCP_OPT_MESSAGE_TYPE           53
#define DHCP_OPT_MESSAGE_TYPE_VAL_LEN   1
#define DHCP_OPT_MESSAGE_TYPE_DISCOVER  1
#define DHCP_OPT_MESSAGE_TYPE_OFFER     2
#define DHCP_OPT_MESSAGE_TYPE_REQUEST   3
#define DHCP_OPT_MESSAGE_TYPE_DECLINE   4
#define DHCP_OPT_MESSAGE_TYPE_ACK       5
#define DHCP_OPT_MESSAGE_TYPE_NAK       6
#define DHCP_OPT_MESSAGE_TYPE_RELEASE   7

#define DHCP_OPT_END                    0xff
#define DHCP_OPT_IDENTIFIER             54
#define DHCP_OPT_IP_ADDR_LEASE          51
#define DHCP_OPT_RENEWAL_TIME           58
#define DHCP_OPT_REBIND_TIME            59
#define DHCP_OPT_SUBNET_MASK            1
#define DHCP_OPT_BROADCAST_ADDR         28
#define DHCP_OPT_ROUTER                 3
#define DHCP_OPT_DNS                    6
#define DHCP_OPT_DOMAIN_NAME            15



struct dpch_option {
    uint8_t tag;
    uint8_t len;
    void *data;
};

struct dhcp_hdr {
    uint8_t op;
    uint8_t hw_type;
    uint8_t hw_len;
    uint8_t hops;
    uint32_t xid;
    uint16_t secs;
    uint16_t flags;
    uint32_t ciaddr;
    uint32_t yiaddr; /* your ip */
    uint32_t siaddr; /* server ip */
    uint32_t giaddr; /* gateway ip */
    uint8_t chaddr[DHCP_CLIENT_HW_ADDR];
    uint8_t sname[DHCP_SERVER_NAME_LEN];
    uint8_t file[DHCP_BOOT_FILE_NAME_LEN];
} __rte_packed;

#define DOMAIN_NAME "lan"

struct rte_mbuf *
process_dhcp(struct rte_mbuf *m, uint16_t port, uint16_t *len);

#endif
