#ifndef ETHERNET_H
#define ETHERNET_H

#include <stdint.h>
#include <rte_mbuf.h>

void
l2_send(struct rte_mbuf *m, struct rte_ether_addr *src, struct rte_ether_addr *dst, uint16_t proto);

void
l2_reply(struct rte_mbuf *m);

#endif