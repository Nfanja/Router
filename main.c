
#include "router.h"


/**
 * Main funciton of router.
 */
int main(int argc, char* argv[]) {
    init_dpdk();
    if (parse_args(argc, argv)==1) {
        main_conf_and_start();
        rte_eal_mp_wait_lcore();
    }

    return 0;

}
