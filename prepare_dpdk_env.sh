#!/bin/bash

export RTE_SDK=dpdk/dpdk

modprobe uio
insmod $RTE_SDK/build/kmod/igb_uio.ko

mount -t hugetlbfs nodev /mnt/huge
echo 1024 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages

$RTE_SDK/usertools/dpdk-devbind.py --bind igb_uio 0000:02:00.0 0000:03:00.0
