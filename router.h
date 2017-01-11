#ifndef ROUTER_H__
#define ROUTER_H__

#include <stdint.h>
#include <unistd.h>
#include <inttypes.h>

#include <rte_config.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_arp.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_byteorder.h>
#include <rte_launch.h>

#include <arpa/inet.h>

#include "dpdk_init.h"
#include "routing_table.h"

struct thread_config {
    uint8_t src_interface;
    uint16_t src_queue;
    uint16_t dst_queue;
    uint32_t port_ip;
    struct ether_addr port_mac;
};

int router_thread(void* arg);
void parse_route(char *route);
int parse_args(int argc, char **argv);
void start_thread(uint8_t port);

void wrong_route(char *route);
struct ether_addr parse_mac(char *mac);
uint32_t parse_ip(char *ip_str);
int parse_port(char *port);
bool is_ip_v4_pckt_valid(struct ipv4_hdr *ip_hdr, uint32_t pckt_len);
void main_conf_and_start();
int split (const char *str, char c, char ***arr);
void usage();


#endif
