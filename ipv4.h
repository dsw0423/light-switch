#ifndef IPV4_H
#define IPV4_h

#include <rte_mbuf.h>

void
process_ipv4(struct rte_mbuf *m);

void
ipv4_reply(struct rte_mbuf *m);

#endif