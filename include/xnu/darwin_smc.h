#pragma once

#include "qemu/osdep.h"
#include "hw/core/sysbus.h"
#include "xnu/apple_dtree.h"

/*
 * Create the SMC coprocessor described by /arm-io/smc: the generic RTKit
 * mailbox (darwin_asc.c) plus a model of the SMC firmware's key protocol
 * on endpoint 0x20 (the "SMCEndpoint1" service AppleSMCKeysEndpoint
 * matches), and the payload SRAM window the device tree's iop-smc-nub
 * node describes. See darwin_smc.c.
 *
 * Returns the darwin-asc DeviceState (as darwin_dcp_create does) or NULL
 * if the node is absent. darwin.c needs only this one call, and "smc"
 * added to its claimed list:
 *
 *     darwin_smc_create(dt_root, iobase, aic);
 *     static const char *const claimed_ascs[] = { "dcp", "sep", "ans", "smc" };
 */
DeviceState *darwin_smc_create(struct dtree_node *dt_root, uint64_t iobase, DeviceState *aic);
