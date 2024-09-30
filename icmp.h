#ifndef ICMP_H
#define ICMP_H

#include <rte_mbuf.h>

#define IPV4_PROTO_TYPE_ICMPV4 0x01

void
process_icmp(struct rte_mbuf *m);

#endif
