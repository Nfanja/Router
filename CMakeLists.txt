CMAKE_MINIMUM_REQUIRED(VERSION 2.8)

SET(CMAKE_C_FLAGS "-Wall -Wextra -Wno-unused-parameter -g -O3 -std=gnu11 -march=native")
SET(CMAKE_CXX_FLAGS "-Wall -Wextra -Wno-unused-parameter -g -O3 -std=gnu++11 -march=native")

# router
SET(PRJ router)
SET(SOURCES dummy_routing_table.c dpdk_init.c router.c)
INCLUDE_DIRECTORIES(
	./dpdk/build/include
)
SET(DPDK_LIBS
	ethdev         rte_distributor rte_mbuf    rte_timer rte_eal   rte_kvargs rte_mempool
	rte_pmd_virtio rte_ring        rte_cfgfile rte_hash  rte_meter rte_sched  rte_cmdline
	rte_port       rte_table
)
LINK_DIRECTORIES(
	${CMAKE_CURRENT_SOURCE_DIR}/dpdk/build/lib
)
ADD_EXECUTABLE(${PRJ} ${SOURCES} main.c)
TARGET_LINK_LIBRARIES(${PRJ} -Wl,--start-group ${DPDK_LIBS} -Wl,--end-group pthread dl rt)

# forwarder
SET(PRJ fwd)
ADD_EXECUTABLE(${PRJ} dpdk_init.c forwarder/fwd.c)
TARGET_LINK_LIBRARIES(${PRJ} -Wl,--start-group ${DPDK_LIBS} -Wl,--end-group pthread dl rt)

