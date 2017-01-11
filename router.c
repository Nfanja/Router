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
#include "router.h"

#define MAX_PORTS 3
#define MIN_PORTS 0
#define MAX_ROUTES 256

char args_delim = ',';
char ip_delim = '.';
char mac_delim = ':';
char mask_delim = '/';

uint32_t ports_ips[MAX_PORTS] = {0};
uint32_t num_ports = 0;
int thr_num = 0;

// struct route {
//     uint8_t depth;
//     uint32_t ip;
//     struct routing_table_entry next_hop;
// };
// struct route routes[MAX_ROUTES];

//void add_route(uint32_t ip_addr, uint8_t prefix, struct ether_addr* mac_addr, uint8_t port) {
// TODO: http://dpdk.org/doc/guides-16.04/prog_guide/lpm_lib.html
//}

void wrong_route(char *route) {
    printf("Wrong route: %s", route);
    usage();
    exit(EXIT_FAILURE);
}

struct ether_addr parse_mac(char *mac) {
    char **mac_strs;
    int n = split(mac, mac_delim, &mac_strs);

    if (n != 6) {
        wrong_route(mac);
    }

    uint8_t mac_addr[6];

    for (int i = 0; i < 6; i++) {
        mac_addr[i] = (uint8_t)strtol(mac_strs[i], NULL, 16);
    }

    struct ether_addr res = {
        //TODO
        .addr_bytes = {mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]}
    };

    return res;
}

void parse_route(char *route) {
    char **args;
    int num_args = split(route, args_delim, &args);

    uint32_t ip;
    uint8_t depth;
    uint8_t dst_port;

    if (num_args != 3) {
        wrong_route(route);
    }

    char **netw;
    int num_netw_args = split(args[0], mask_delim, &netw);

    if (num_netw_args != 2) {
        wrong_route(route);
    }

    ip = parse_ip(netw[0]);
    depth = atoi(netw[1]);

    if (depth > 32) {
        wrong_route(route);
    }

    dst_port = atoi(args[2]);

    if (dst_port > MAX_PORTS - 1) {
        wrong_route(route);
    }

    struct ether_addr mmac= (parse_mac(args[1]));
    //add_route(ip, depth, &mmac, dst_port);
    //TODO: routing_table.h
}

uint32_t parse_ip(char *ip_str) {
    char **sp = NULL;
    int num_ip_args = split(ip_str, ip_delim, &sp);

    if (num_ip_args != 4){
        return 0;
    }

    return rte_cpu_to_be_32(IPv4(atoi(sp[0]), atoi(sp[1]), atoi(sp[2]), atoi(sp[3])));
}


int parse_port(char *port_str) {
    char **args = NULL;
    int num_args = split(port_str, args_delim, &args);

    if (num_args != 2){
        return -1;
    }

    uint8_t port = atoi(args[0]);

    if (port > MAX_PORTS - 1){
        printf("Number of ports is from %d to %d", MIN_PORTS, MAX_PORTS -1);
        return -1;
    }

    uint32_t ip = parse_ip(args[1]);

    if (ip == 0){
        return -1;
    }

    ports_ips[port] = ip;
    return 0;
}

int parse_args(int argc, char **argv) {
    int opt;
    while ((opt = getopt(argc, argv, "p:r:")) != EOF) {
        switch(opt) {
            case 'p':
                if (parse_port(optarg) != 0) {
                    usage();
                    return -1;
                }
                num_ports++;
                break;
            case 'r':
                parse_route(optarg);
                break;
            default:
                return -1;
        }
    }
    return 1;
}

void usage() {
    printf("Simple DPDK Router\n-p\trecieves the interface id of the router interface followed by an IP address\n-r\tSpecifies routes. Routes are tuple of a network and simplified next hop. A network is an IP address and a netmask given in CIDR notation. We use a MAC address and destination interface id as a simplified hop\n./router -p 0,10.0.10.1 -r 10.0.10.2/32,52:54:00:cb:ee:f4,0");
}

/*
 * rfc 1812
 *
 *  (1) The packet length reported by the Link Layer must be large enough
 *          to hold the minimum length legal IP datagram (20 bytes).
 *
 *  (2) The IP checksum must be correct.
 *
 *  (3) The IP version number must be 4.  If the version number is not 4
 *      then the packet may be another version of IP, such as IPng or
 *      ST-II.
 *
 *  (4) The IP header length field must be large enough to hold the
 *      minimum length legal IP datagram (20 bytes = 5 words).
 *
 *  (5) The IP total length field must be large enough to hold the IP
 *      datagram header, whose length is specified in the IP header
 *      length field.
 */

// ./dpdk/examples/l3fwd-acl/main.c
bool is_ip_v4_pckt_valid(struct ipv4_hdr *ip_hdr, uint32_t pckt_len) {
    // 1
    if (pckt_len < sizeof(struct ipv4_hdr)) {
        return false;
    }

    // 2 correctnes of packet already checked at 2nd level

    // 3 version and header length in 8 bits
    if ( ((ip_hdr->version_ihl)>>4) != 4) {
        return false;
    }
    // 4
    if ( (ip_hdr->version_ihl & 0xf) < 5) {
        return false;
    }

    // 5
    if (rte_cpu_to_be_16(ip_hdr->total_length) < sizeof(struct ipv4_hdr)) {
        return false;
    }

    return true;
}

void transmit_packet(uint8_t port, uint16_t dst_queue, struct rte_mbuf* buf){
    while (!rte_eth_tx_burst(port, dst_queue, &buf, 1));
}

void start_thread(uint8_t port) {
    struct thread_config* config = (struct thread_config*) malloc(sizeof(struct thread_config));
    config->src_interface = port;
    config->src_queue = 0;
    config->dst_queue = port;
    config->port_ip = ports_ips[port];
    rte_eth_macaddr_get(port, &config->port_mac);
    thr_num++;
    rte_eal_remote_launch(router_thread, config, thr_num);
}

int router_thread(void *arg) {
    struct thread_config* config = (struct thread_config*) arg;
    struct rte_mbuf* bufs[64];

    while (1) {
        uint16_t rx = rte_eth_rx_burst(config->src_interface, config->src_queue,
                bufs, 64);
        
        for (uint16_t i = 0; i < rx; i++) {
            // ./dpdk/lib/librte_ether/rte_ether.h
            struct ether_hdr* eth_hdr = rte_pktmbuf_mtod(bufs[i],
                    struct ether_hdr*);
            //packets come in BE format
            uint16_t pckt_type = rte_be_to_cpu_16(eth_hdr->ether_type);

            // IPv4
            // ./dpdk/lib/librte_net/rte_ip.h
            if (pckt_type == ETHER_TYPE_IPv4) {
                struct ipv4_hdr *v4_hdr = rte_pktmbuf_mtod_offset(bufs[i],
                        struct ipv4_hdr *,
                        sizeof(struct ether_hdr));

                if(!is_ip_v4_pckt_valid(v4_hdr, bufs[i]->pkt_len)) {
                    printf("invalid packet ip4");
                    rte_pktmbuf_free(bufs[i]);
                    continue;
                }

                struct routing_table_entry * next_hop = get_next_hop(v4_hdr->dst_addr);
                if (next_hop == NULL) {
                    rte_pktmbuf_free(bufs[i]);
                    continue;
                }
                uint8_t dst_port = next_hop->dst_port;
                struct ether_addr dst_mac = next_hop->dst_mac;
                eth_hdr->s_addr = config->port_mac;
                eth_hdr->d_addr = dst_mac;

                transmit_packet(dst_port, config->dst_queue, bufs[i]);
            }
            else if (pckt_type == ETHER_TYPE_ARP) {
// ./dpdk/lib/librte_net/rte_arp.h
//
// struct arp_hdr {
// 	uint16_t arp_hrd;    /* format of hardware address */
// #define ARP_HRD_ETHER     1  /* ARP Ethernet address format */
// 
// 	uint16_t arp_pro;    /* format of protocol address */
// 	uint8_t  arp_hln;    /* length of hardware address */
// 	uint8_t  arp_pln;    /* length of protocol address */
// 	uint16_t arp_op;     /* ARP opcode (command) */
// #define	ARP_OP_REQUEST    1 /* request to resolve address */
// #define	ARP_OP_REPLY      2 /* response to previous request */
// #define	ARP_OP_REVREQUEST 3 /* request proto addr given hardware */
// #define	ARP_OP_REVREPLY   4 /* response giving protocol address */
// #define	ARP_OP_INVREQUEST 8 /* request to identify peer */
// #define	ARP_OP_INVREPLY   9 /* response identifying peer */
// 
// 	struct arp_ipv4 arp_data;
// } __attribute__((__packed__));

                struct arp_hdr *arp_h = rte_pktmbuf_mtod_offset(bufs[i], struct arp_hdr*,
                    sizeof(struct ether_hdr));
                
                // router recieves reqest
                if (arp_h->arp_op == rte_cpu_to_be_16(ARP_OP_REQUEST)) {
                    uint32_t src_ip;
                    if (arp_h->arp_data.arp_tip == config->port_ip) {
                        src_ip = config->port_ip;
                    }
                    else {
                        src_ip = arp_h->arp_data.arp_tip;
                    }

                    // response creation
                    // ./dpdk/app/test-pmd/icmpecho.c
                    arp_h->arp_op = rte_cpu_to_be_16(ARP_OP_REPLY);
                    ether_addr_copy(&arp_h->arp_data.arp_sha, &arp_h->arp_data.arp_tha);
                    arp_h->arp_data.arp_sha = config->port_mac;
                    arp_h->arp_data.arp_tip = arp_h->arp_data.arp_sip;
                    arp_h->arp_data.arp_sip = src_ip;

                    //change dest and src macs
                    ether_addr_copy(&eth_hdr->s_addr, &eth_hdr->d_addr);
                    eth_hdr->s_addr = config->port_mac;

                    transmit_packet(config->src_interface, config->dst_queue, bufs[i]);
                }
            }
            rte_pktmbuf_free(bufs[i]);
        }
    }
    return 1;
}

void main_conf_and_start(){
    for (uint8_t i = 0; i < MAX_PORTS; i++) {
        if (ports_ips[i] != 0) {
            configure_device(i, num_ports);
            start_thread(i);
        }
    }
}

// http://stackoverflow.com/a/24567731
// splits string into array of strings
int split (const char *str, char c, char ***arr)
{
    int count = 1;
    int token_len = 1;
    int i = 0;
    char *p;
    char *t;

    p = str;
    while (*p != '\0')
    {
        if (*p == c)
            count++;
        p++;
    }

    *arr = (char**) malloc(sizeof(char*) * count);
    if (*arr == NULL)
        exit(1);

    p = str;
    while (*p != '\0')
    {
        if (*p == c)
        {
            (*arr)[i] = (char*) malloc( sizeof(char) * token_len );
            if ((*arr)[i] == NULL)
                exit(1);

            token_len = 0;
            i++;
        }
        p++;
        token_len++;
    }
    (*arr)[i] = (char*) malloc( sizeof(char) * token_len );
    if ((*arr)[i] == NULL)
        exit(1);

    i = 0;
    p = str;
    t = ((*arr)[i]);
    while (*p != '\0')
    {
        if (*p != c && *p != '\0')
        {
            *t = *p;
            t++;
        }
        else
        {
            *t = '\0';
            i++;
            t = ((*arr)[i]);
        }
        p++;
    }

    return count;
}
