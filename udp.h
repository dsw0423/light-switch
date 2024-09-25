#ifndef UDP_H
#define UDP_H

#include <rte_mbuf.h>
#include <stdint.h>

struct rte_mbuf *
process_udp(struct rte_mbuf *m, uint16_t port);

#endif