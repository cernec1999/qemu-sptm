/*
 * darwin-smc: the System Management Controller, modelled
 *
 * The SMC is an ASC-family coprocessor (device tree "iop,ascwrap-v6",
 * role "SMC"), so its wrapper and mailbox are the generic ones in
 * darwin_asc.c. What lives above the mailbox is not AFK/EPIC: the AP
 * side (AppleSMC.kext) speaks a small key/value protocol over a single
 * RTKit endpoint, and this file models the firmware half of it.
 *
 * The contract below was reverse engineered from the iOS 27.0.1 (24A446)
 * kernelcache; the SYS147 entry in REPORT.md carries the full evidence
 * trail (function addresses are that kernelcache's, unslid).
 *
 * Discovery
 *
 *   RTBuddy names endpoint services "%sEndpoint%u" from the coprocessor's
 *   role and (endpoint - 0x1f) — endpoint 0x20 on the DCP is
 *   "DCPEndpoint1", endpoint 0x20 here is "SMCEndpoint1". AppleSMC's
 *   keys-endpoint personality matches exactly that service name, so
 *   advertising endpoint 0x20 in the RTKit endpoint map is the whole
 *   discovery obligation. AppleSMC then manufactures one
 *   AppleSMCInterface service per device-tree function child of the
 *   SMC (smc-pmu, smc-charger, ...), and the drivers for those
 *   functions (AppleSMCPMU, the charger stack, ...) match the
 *   interfaces by name.
 *
 * Key protocol (AppleSMCKeysEndpoint), one 64-bit message per request
 *
 *   request   byte 0   opcode
 *             byte 1   tag: (rolling 4-bit sequence << 4) | channel
 *                      (the channel is 0 on this platform)
 *             byte 2   payload size for reads/writes
 *             byte 3   0
 *             bytes 4-7  key FourCC, or the index for opcode 0x12
 *
 *   response  byte 0   result (0 = success, 0x84 = key not found)
 *             byte 1   tag echo — the AP drops mismatched responses
 *             byte 2   payload length
 *             byte 3   0
 *             bytes 4-7  payload, when its length is at most 4
 *
 *   opcodes   0x10 read key        0x11 write key
 *             0x12 key from index  0x13 key info
 *             0x17 SRAM address (request is the bare word 0x17)
 *
 *   Payloads longer than 4 bytes, every write payload, and the 6-byte
 *   key-info struct travel through the SRAM window instead of the
 *   message: the AP stages write data at the window base before sending
 *   the request and reads results back from the window base after the
 *   response. The window's address is the answer to opcode 0x17 — the
 *   response word is the bare physical address — and the AP validates
 *   it against the iop-smc-nub node's "region-base"/"region-size"
 *   device-tree properties before mapping it, so this model backs
 *   exactly that range with RAM and answers with its base.
 *
 *   Key info struct (6 bytes at the window base):
 *     [0] key size, [1..4] key type FourCC (big-endian), [5] attributes.
 *
 *   The key directory is enumerated over the protocol, not read from
 *   the window: '#KEY' reads as the directory size (big-endian), and
 *   opcode 0x12 maps an index to a key FourCC (big-endian).
 *
 * Key set
 *
 *   The directory holds the keys this model serves: '#KEY' itself and
 *   'MSLD', the lid-state key AppleSMCPMU reads at start to publish
 *   AppleClamshellState. An iPhone has no lid to close: MSLD reads 0
 *   ("lid open"), one byte, type 'ui8 '. Everything else is answered
 *   with the protocol's not-found result (0x84), which every boot-path
 *   consumer in AppleSMC is written to tolerate (it is how the AP
 *   learns e.g. that there are no 'aDC#' ADC channels to create
 *   sensors for, and that 'RGEN' has no generation byte). 'NTAP', the
 *   notification-arm key AppleSMC writes at start, is accepted as a
 *   write without a directory entry.
 *
 *   Every request is logged to stderr. That log is deliberate: it is
 *   the census of what the guest's SMC clients actually ask for, and
 *   the key set grows from it, with evidence, not by invention.
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "hw/core/sysbus.h"
#include "system/memory.h"
#include "system/address-spaces.h"
#include "xnu/apple_dtree.h"
#include "xnu/darwin_asc.h"
#include "xnu/darwin_smc.h"

#define SMC_KEYS_ENDPOINT 0x20

/* opcodes */
#define SMC_OP_READ_KEY        0x10
#define SMC_OP_WRITE_KEY       0x11
#define SMC_OP_KEY_FROM_INDEX  0x12
#define SMC_OP_KEY_INFO        0x13
#define SMC_OP_SRAM_ADDRESS    0x17

/* results */
#define SMC_OK            0x00
#define SMC_KEY_NOT_FOUND 0x84

typedef struct {
    uint32_t key;       /* FourCC as a host-order constant, e.g. 'MSLD' */
    uint32_t type;      /* FourCC type tag, e.g. 'ui8 ' */
    uint8_t  size;      /* value length in bytes */
    uint8_t  value[4];  /* value bytes, in wire (big-endian) order */
} SMCKey;

typedef struct {
    DeviceState *asc;
    MemoryRegion sram;
    uint64_t sram_base;
    uint64_t sram_size;
    uint8_t *sram_ptr;
} DarwinSMC;

/*
 * The key directory. '#KEY' is index 0; its value (the directory size,
 * this table's length) is filled in by smc_key_value() rather than
 * stored, so the table cannot disagree with itself.
 */
static const SMCKey smc_keys[] = {
    { '#KEY', 'ui32', 4, { 0, 0, 0, 0 } },
    { 'MSLD', 'ui8 ', 1, { 0 } },   /* lid state: 0 = open */
};

static const SMCKey *smc_find_key(uint32_t key)
{
    for (size_t i = 0; i < ARRAY_SIZE(smc_keys); i++) {
        if (smc_keys[i].key == key) {
            return &smc_keys[i];
        }
    }
    return NULL;
}

static void smc_key_name(uint32_t key, char name[5])
{
    name[0] = (key >> 24) & 0xff;
    name[1] = (key >> 16) & 0xff;
    name[2] = (key >> 8) & 0xff;
    name[3] = key & 0xff;
    name[4] = 0;
    for (int i = 0; i < 4; i++) {
        if (name[i] < 0x20 || name[i] > 0x7e) {
            name[i] = '.';
        }
    }
}

/*
 * Copy a key's value out in wire order. Returns its length, or -1 if
 * the key is not in the directory.
 */
static int smc_key_value(const SMCKey *k, uint8_t *out)
{
    if (k->key == '#KEY') {
        uint32_t n = ARRAY_SIZE(smc_keys);
        out[0] = (n >> 24) & 0xff;
        out[1] = (n >> 16) & 0xff;
        out[2] = (n >> 8) & 0xff;
        out[3] = n & 0xff;
        return 4;
    }
    memcpy(out, k->value, k->size);
    return k->size;
}

static void smc_respond(DarwinSMC *s, uint8_t result, uint8_t tag,
                        const uint8_t *payload, uint8_t len)
{
    uint64_t resp = (uint64_t)result | ((uint64_t)tag << 8) |
                    ((uint64_t)len << 16);
    if (payload && len) {
        if (len <= 4) {
            for (int i = 0; i < len; i++) {
                resp |= (uint64_t)payload[i] << (32 + 8 * i);
            }
        } else if (s->sram_ptr) {
            /* Long payloads travel through the SRAM window, staged
             * before the response so the AP reads them after it. */
            memcpy(s->sram_ptr, payload, len);
        }
    }
    darwin_asc_send(s->asc, SMC_KEYS_ENDPOINT, resp);
}

static bool smc_handle(void *opaque, uint8_t ep, uint64_t msg)
{
    DarwinSMC *s = opaque;
    if (ep != SMC_KEYS_ENDPOINT) {
        return false;
    }
    uint8_t opcode = msg & 0xff;
    uint8_t tag = (msg >> 8) & 0xff;
    uint8_t size = (msg >> 16) & 0xff;
    uint32_t arg = (msg >> 32) & 0xffffffff;
    char name[5];

    switch (opcode) {
    case SMC_OP_SRAM_ADDRESS:
        /* The response word is the bare SRAM address; the AP range-
         * validates it against the device tree before mapping it. */
        fprintf(stderr, "smc: sram-address request -> 0x%" PRIx64 "\n",
                s->sram_base);
        darwin_asc_send(s->asc, SMC_KEYS_ENDPOINT, s->sram_base);
        return true;

    case SMC_OP_READ_KEY: {
        const SMCKey *k = smc_find_key(arg);
        smc_key_name(arg, name);
        if (!k) {
            fprintf(stderr, "smc: read '%s' size %u -> not found\n",
                    name, size);
            smc_respond(s, SMC_KEY_NOT_FOUND, tag, NULL, 0);
            return true;
        }
        uint8_t value[120];
        int len = smc_key_value(k, value);
        fprintf(stderr, "smc: read '%s' size %u -> ok, %d bytes\n",
                name, size, len);
        smc_respond(s, SMC_OK, tag, value, (uint8_t)len);
        return true;
    }

    case SMC_OP_WRITE_KEY: {
        smc_key_name(arg, name);
        uint8_t first = (size && s->sram_ptr) ? s->sram_ptr[0] : 0;
        if (arg == 'NTAP') {
            /* Notification arm: AppleSMC writes 1 here at start. The
             * value arrives staged in the SRAM window. */
            fprintf(stderr, "smc: write 'NTAP' size %u value %u -> ok"
                    " (notifications armed)\n", size, first);
            smc_respond(s, SMC_OK, tag, NULL, 0);
            return true;
        }
        fprintf(stderr, "smc: write '%s' size %u -> not found\n",
                name, size);
        smc_respond(s, SMC_KEY_NOT_FOUND, tag, NULL, 0);
        return true;
    }

    case SMC_OP_KEY_FROM_INDEX: {
        if (arg >= ARRAY_SIZE(smc_keys)) {
            fprintf(stderr, "smc: key-from-index %u -> not found\n", arg);
            smc_respond(s, SMC_KEY_NOT_FOUND, tag, NULL, 0);
            return true;
        }
        uint32_t key = smc_keys[arg].key;
        uint8_t payload[4] = {
            (key >> 24) & 0xff, (key >> 16) & 0xff,
            (key >> 8) & 0xff, key & 0xff,
        };
        smc_key_name(key, name);
        fprintf(stderr, "smc: key-from-index %u -> '%s'\n", arg, name);
        smc_respond(s, SMC_OK, tag, payload, 4);
        return true;
    }

    case SMC_OP_KEY_INFO: {
        const SMCKey *k = smc_find_key(arg);
        smc_key_name(arg, name);
        if (!k) {
            fprintf(stderr, "smc: info '%s' -> not found\n", name);
            smc_respond(s, SMC_KEY_NOT_FOUND, tag, NULL, 0);
            return true;
        }
        /* The info struct always travels through the SRAM window. */
        uint8_t info[6] = {
            k->size,
            (k->type >> 24) & 0xff, (k->type >> 16) & 0xff,
            (k->type >> 8) & 0xff, k->type & 0xff,
            0, /* attributes: no boot-path consumer interprets them */
        };
        if (s->sram_ptr) {
            memcpy(s->sram_ptr, info, sizeof(info));
        }
        fprintf(stderr, "smc: info '%s' -> size %u type '%c%c%c%c'\n",
                name, k->size,
                (k->type >> 24) & 0xff, (k->type >> 16) & 0xff,
                (k->type >> 8) & 0xff, k->type & 0xff);
        smc_respond(s, SMC_OK, tag, NULL, (uint8_t)sizeof(info));
        return true;
    }

    default:
        fprintf(stderr, "smc: unhandled opcode 0x%02x tag 0x%02x"
                " arg 0x%08x -> not found\n", opcode, tag, arg);
        smc_respond(s, SMC_KEY_NOT_FOUND, tag, NULL, 0);
        return true;
    }
}

static void smc_started(void *opaque)
{
    fprintf(stderr, "smc: RTKit handshake complete\n");
}

static void smc_ep_start(void *opaque, uint8_t ep, uint32_t flag)
{
    fprintf(stderr, "smc: AP %s endpoint 0x%02x\n",
            flag == 2 ? "started" : "stopped", ep);
}

static const DarwinASCOps smc_asc_ops = {
    .started = smc_started,
    .ep_start = smc_ep_start,
    .handle = smc_handle,
};

static const uint8_t smc_eps[] = { SMC_KEYS_ENDPOINT };

DeviceState *darwin_smc_create(struct dtree_node *dt_root, uint64_t iobase,
                               DeviceState *aic)
{
    struct dtree_node *smc = adt_find_node(dt_root, "arm-io/smc");
    if (!smc) {
        return NULL;
    }
    DarwinSMC *s = g_new0(DarwinSMC, 1);

    /*
     * The payload SRAM window is described by the IOP nub child, the
     * same properties the AP validates the SRAM-address answer
     * against. Back exactly that range.
     */
    struct dtree_node *nub = adt_find_node(dt_root, "arm-io/smc/iop-smc-nub");
    uint64_t *base = nub ? adt_get_prop_val(nub, "region-base") : NULL;
    uint64_t *size = nub ? adt_get_prop_val(nub, "region-size") : NULL;
    if (base && size && *size) {
        s->sram_base = *base;
        s->sram_size = *size;
    } else {
        fprintf(stderr, "smc: iop-smc-nub has no region-base/region-size;"
                " key payloads over 4 bytes will fail\n");
    }

    s->asc = darwin_asc_create(smc, iobase, aic, smc_eps,
                                ARRAY_SIZE(smc_eps), &smc_asc_ops, s);
    if (!s->asc) {
        g_free(s);
        return NULL;
    }

    if (s->sram_size) {
        memory_region_init_ram(&s->sram, OBJECT(s->asc), "smc-sram",
                               s->sram_size, &error_fatal);
        s->sram_ptr = memory_region_get_ram_ptr(&s->sram);
        memory_region_add_subregion(get_system_memory(), s->sram_base,
                                    &s->sram);
    }

    fprintf(stderr, "darwin-smc: keys endpoint 0x%02x (SMCEndpoint1),"
            " sram window 0x%" PRIx64 "+0x%" PRIx64 ", %zu keys\n",
            SMC_KEYS_ENDPOINT, s->sram_base, s->sram_size,
            ARRAY_SIZE(smc_keys));
    return s->asc;
}
