# Copyright 2017 Intel Corporation.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

PATH_TO_MK = ../mk
IMAGENAME = nff-go-dpdk-nat
EXECUTABLES = dpdk_vpn
#SUBDIRS = tutorial antiddos demo fileReadWrite firewall forwarding ipsec lb nffPktgen

.PHONY: dpi
dpi:
	$(MAKE) -C dpi

include $(PATH_TO_MK)/intermediate.mk
include $(PATH_TO_MK)/leaf.mk
