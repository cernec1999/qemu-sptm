/*
 * darwin-iomfb: the DCP "link" protocol on endpoint 0x37, firmware side.
 *
 * Endpoint 0x37 is DCPEndpoint24 / AppleDCPLinkServiceSoC, the endpoint the
 * *framebuffer* rides on. It is NOT AFK and NOT EPIC: the 64-bit RTKit
 * mailbox word is itself the message, with a structured 16-bit header in the
 * low bits and a class-dependent payload above it.
 *
 * SOURCE for everything below: iOS 27.0 beta (24A5430a), iPhone17,3
 * (t8140/H17P), kernelcache firmware/bootkc, fileset entry
 * com.apple.iokit.IOMobileGraphicsFamily-DCP. The kext is stripped (nsyms=0),
 * so functions are named by string cross-reference. Unslid VAs; the panic
 * addresses the guest prints are these + 0x20000000. The long-form write-up
 * with the reasoning is docs/re/iomfb-link.md.
 *
 *   link_send_message      fcn.fffffff00a0cecd0
 *   link_handle_message    fcn.fffffff00a0cfac0   (the AP's receive dispatcher)
 *   link_init_ack step     fcn.fffffff00a0ce0f0
 *   rpc_caller_gated       fcn.fffffff00a0ce46c   (aka link_shared_alloc)
 *   the heap announce      fcn.fffffff00a0cdfe0
 *
 * ---------------------------------------------------------------- header --
 *
 * link_send_message builds, and link_handle_message dispatches on, exactly
 * these fields. The 48-bit boundary is the literal operand of
 * `and x8, x2, 0xffffffffffff0000` at 0xa0ced14 -- not an inference.
 *
 *   [1:0]    class    `and w26, w28, 3`      @ 0xa0cfb04
 *   [5:2]    unused   (zero in every message seen, read by nobody)
 *   [7:6]    subkind  `ubfx w0, w28, 6, 2`   @ 0xa0cfb14
 *   [8]      ack bit  `bfi ..., 8, 1`        @ 0xa0ced10, keyed on @ 0xa0cfc48
 *   [9]      flag     passed through by the sender (`x2 & 0x2ff` keeps it)
 *   [15:10]  6-bit tag `(*ctx & 0x3f) << 10` @ 0xa0ced00, extracted @ 0xa0cfc4c
 *   [63:16]  payload, meaning depends on class
 *
 * ------------------------------------------------------------- the flow --
 *
 * 1. AP -> IOP, class 0 / subkind 1: "here is my shared heap".
 *    Built at 0xa0ce074 as `0x40 | (dva << 16)`; observed
 *    0x0100000000000040, i.e. DVA 0x10000000000. It is SEND-ONLY: echoing it
 *    back makes the AP take link_handle_message's own class-0/subkind-1
 *    branch (0xa0d0008), which unconditionally logs
 *    "link_init_ack_callback failed with 0x6" and returns kIOReturnNoMemory,
 *    panicking at AppleDCPLinkService.cpp:882. Verified live.
 *
 * 2. IOP -> AP, class 1: the init ack. link_handle_message's class-1 branch
 *    (0xa0cfb5c) computes
 *      local  = crc32(0, (uint8_t*)0xfffffff00b880c70, 4)   @ 0xa0cfb60-b6c
 *    and compares it 32-bit against
 *      remote = (msg >> 16) & 0xffffffff                    @ 0xa0cfb9c-ba0
 *    Those four bytes of the kext's own __DATA are `d3 00 00 00` (bootkc file
 *    offset 0x487cc70), and zlib.crc32(b"\xd3\0\0\0") == 0x15a5c96b, which is
 *    exactly the `local=` the guest printed when we got this wrong. So the
 *    constant is reproduced from first principles rather than copied out of a
 *    panic -- but it is specific to THIS kernelcache; recompute it from those
 *    bytes for a different build. Bits[63:48] are a phase/count the AP stores
 *    as max(phase, 4) at chan+0x48 (0xa0cfbe4-0xa0cfc00), so 0 is safe.
 *
 * 3. AP -> IOP, class 2 / subkind 0: "there is an RPC request in the heap".
 *    Built by rpc_caller_gated at 0xa0ce65c-0xa0ce688:
 *        x24 = offset; bfi w24, w25, 16, 16     ; w25 = total size
 *        x25 = 2; bfi x25, x23, 9, 1            ; class 2, bit 9 = a caller flag
 *        x2  = x25 | (x24 << 16)
 *    i.e. bits[31:16] = byte offset into the heap, bits[47:32] = total size.
 *    The request itself is written into the heap at that offset by
 *    0xa0ce608-0xa0ce654:
 *        +0x00  u32  name    a FourCC, printed big-endian at 0xa0ce4a8-4c4
 *        +0x04  u32  in_len
 *        +0x08  u32  out_len
 *        +0x0c  u8   in[in_len]
 *        +0x0c+in_len  u8 out[out_len]   <- the IOP fills this in
 *    and total size == 0xc + in_len + out_len (`add w11,w26,0xc;
 *    adds w25,w22,w11` @ 0xa0ce4d8-4dc). The caller then blocks in
 *    link_cond_wait_priv.
 *
 * 4. IOP -> AP, class 2 / subkind 1: the completion. The waiter checks
 *        (reply_header & 0xc3) == 0x42                      @ 0xa0ce750-75c
 *    -- 0xc3 masks class and subkind, 0x42 is class 2 + subkind 1 -- and then
 *        status = (u32)(reply >> 16); if (status) fail       @ 0xa0ce78c-790
 *        memcpy(caller_out, heap + offset + 0xc + in_len, out_len)  @ 0xa0ce7c8-7dc
 *    The reply is routed back to the right caller by a lookup keyed on
 *    (ack_bit << 32) | tag (0xa0cfc44-4c), so the reply must carry the
 *    request's own tag and ack bit. Class 2 + subkind 1 is also the one
 *    combination link_send_message REQUIREs you not to send directly
 *    (0xa0ced2c-38) -- it is reply-only, which is a second confirmation that
 *    this is the completion shape.
 *
 * -------------------------------------------- 5. the callee direction (D) --
 *
 * The same class-2 layer runs the other way: the firmware originates a
 * request and the AP answers it. That is the "D-series", and it is how the
 * DCP drives display bring-up past the point our AP-only model reaches.
 * Derived in full in docs/re/iomfb-dseries.md; the parts the code below
 * depends on:
 *
 *  - Correlation. link_handle_message builds a key (ack << 32) | tag from
 *    every class-2 message (0xa0cfc44-0xa0cfc4c) and hands it to the lambda
 *    at 0xa0d0318, which picks one of TWO four-entry slot arrays --
 *    chan+0x78 when the ack bit equals chan[0x70], chan+0x218 when it does
 *    not (0xa0d0328-0xa0d0334) -- and indexes it by the tag, which must be
 *    < 4 (0xa0d033c, else a REQUIRE-fail). So the "6-bit tag" is really a
 *    2-bit slot index per direction.
 *
 *  - Which ack bit. link_state_init stores zero to chan[0x70]
 *    (`str wzr, [x19, #0x260]` at 0xa0cf5e8, and chan == L+0x1f0), and
 *    link_send_message sources bit 8 from that same byte when no ctx is
 *    passed -- which is exactly why the AP's own announce and its own RPC
 *    requests have bit 8 clear. An inbound request must therefore set
 *    **bit 8**, or it lands in the AP's own outgoing slot array.
 *
 *    That direction bit remains set for AP calls nested inside a D-series
 *    handler.  The iOS 27 D120 handler at 0xfffffff00919b338 enters its boot
 *    continuation at 0xfffffff009188040; that continuation's first nested
 *    A389 wrapper is 0xfffffff00917f11c (FourCC build at 0x917f124), and its
 *    live messages are class 2 / subkind 0 / ack 1.  This is also the stack
 *    rule used by the independent Asahi implementations: Linux
 *    drivers/gpu/drm/apple/iomfb.c:dcp_call_context() selects callback context
 *    when channel depth is nonzero, and m1n1 fw/dcp/manager.py:DCPManager
 *    selects CallContext.CB while in_callback.  Therefore ack 1 distinguishes
 *    callback context, not "not an AP request".
 *
 *  - Where the bytes go. link_state_init allocates one 0x80000 heap
 *    (0xa0cf5cc) and carves it into eight fixed 32 KB windows
 *    (0xa0cf654-0xa0cf6e0). The AP's own request for tag t is at
 *    heap + t*0x8000 + offset (slot+8); an inbound request for tag t is at
 *    heap + 0x40000 + t*0x8000 + offset (slot+0x18), which is the pointer
 *    rpc_callee_gated actually dereferences (0xa0cf0d0). The offset field is
 *    relative to that window, not to the heap.
 *
 *  - What the AP checks (rpc_callee_gated, fcn.fffffff00a0cf020): class 2,
 *    subkind != 1, size >= 0xc, size == 0xc + in_len + out_len, and the
 *    whole thing inside the 32 KB window. Then it calls
 *      handler(chan, slot, in, in_len, out, out_len)      @ 0xa0cf1e8-1fc
 *    found by a virtual link_rpc_lookup at vtable+0x540 of chan[0x68].
 *
 *  - The completion it sends back (0xa0cf298-0xa0cf2b4):
 *      msg = (our_header & 0xff3e) | 0x40 | (our bits[63:48] << 48)
 *    i.e. class 2 subkind 1, our tag and our ack bit, and **status 0 in
 *    bits[47:16]** on success. The output it wrote is at
 *    window + offset + 0xc + in_len.
 *
 * ------------------------------------------------------- what is stubbed --
 *
 * The RPC methods themselves, in both directions.
 *
 * Inbound (A-series): we log every FourCC and hexdump its input, and answer
 * with status 0 and a zeroed output buffer. That is a deliberate, documented
 * hole: no method's semantics have been derived from this firmware, so
 * returning "success, all zeroes" is the only answer that does not invent
 * behaviour. Where it is wrong the AP will say so by name, which is how the
 * next method gets modelled.
 *
 * Outbound (D-series): the transport is modelled, the *policy* is not. This
 * file has no opinion about which callback a real DCP would send, or when.
 * DARWIN_DCP_IOMFB_CB is an experiment harness that issues a scripted list so
 * a boot can answer "does the AP accept this name, and what does it do next";
 * with the variable unset nothing is ever sent. docs/re/iomfb-dseries.md has
 * the 139 names link_rpc_lookup accepts and the buffer sizes each handler
 * demands, which is what a script is written from.
 *
 * Class 3 is never sent by either side here and is not modelled. Class 2 /
 * subkind 0 messages with a heap we have not been told about are logged and
 * dropped rather than guessed at.
 *
 * Tracing and knobs: DARWIN_DCP_IOMFB selects the level (see
 * darwin_iomfb.h); DARWIN_DCP_IOMFB_DEBUG=1 adds a hexdump of every RPC
 * request and reply body. DARWIN_DCP_IOMFB_RPC_TRACE=1 is the narrower
 * reverse-engineering trace: every AP-originated call gets one context line
 * with its slot, heap/request DVAs and lengths, while the first occurrence of
 * each exact request body gets a bounded sparse input dump. This is intended
 * to identify this build's real swap-submit method and its surf_iova field
 * without assuming that Mac-era method IDs or layouts survived on iOS.
 * DARWIN_DCP_IOMFB_OUT='A401=01,...' substitutes canned output bytes for one
 * FourCC so a probe can test a hypothesis without a rebuild. Level 4 is that
 * same mechanism with the answers a measurement has already justified (see
 * iomfb_level4[]).
 * DARWIN_DCP_IOMFB_CB='D000,@A385,D003:00000000:14' scripts outbound
 * callbacks; an @NAME item is a barrier that waits for that later AP RPC
 * before the following callback is sent. DARWIN_DCP_IOMFB_CB_AFTER names
 * what starts the script. Every line is prefixed "iomfb:", which
 * tools/probe.sh filters on.
 *
 * DARWIN_DCP_IOMFB_HOTPLUG=1 turns on a native one-shot producer for the
 * D575 hot-plug-detect callback: once the AP's A389 display query has been
 * answered (A389 is RPC #4 at IOMFB bring-up; A385 polling
 * starts too late, after backboardd's HPD registration) and a further DARWIN_DCP_IOMFB_HOTPLUG_DELAY seconds (default
 * 30) of guest time have passed, the model sends a single D575 (event 1,
 * trailing bool 1, optional structure suppressed) through the same
 * callback transport as the scripted harness. The packet shape is the
 * one the guest's D575 handler declares -- in_len 0x58, out_len 0x4c,
 * event u64 at +0, bool at +0x53, optional-structure flag at +0x54 --
 * read out of the handler at 0xfffffff00a1964e4 and the latch it drives
 * (IOMobileFramebufferAP::hotPlug_notify_gated, 0xfffffff00a178c04) in
 * the iOS 27.0.1 (24A446) kernelcache; the fork's 24A5430a decode in
 * docs/re/iomfb-hotplug-swap-gate.md agrees field for field. A real DCP
 * raises hot-plug detect when its display pipeline comes up; this model
 * has no other source for the event, so the producer is opt-in and
 * one-shot, with a fail latch instead of retries.
 */

#include "qemu/osdep.h"
#include "xnu/darwin_fb.h"
#include "qapi/error.h"
#include "migration/vmstate.h"
#include "qemu/timer.h"
#include "hw/arm/darwin_iomfb_swap.h"
#include "system/memory.h"
#include "system/address-spaces.h"
#include "exec/memattrs.h"
#include "xnu/darwin_asc.h"
#include "xnu/darwin_dart.h"
#include "xnu/darwin_iomfb.h"

/* Header field accessors -- see the table above. */
#define IOMFB_CLASS(m)    ((unsigned)((m) & 0x3))
#define IOMFB_SUBKIND(m)  ((unsigned)(((m) >> 6) & 0x3))
#define IOMFB_ACK(m)      ((unsigned)(((m) >> 8) & 0x1))
#define IOMFB_FLAG9(m)    ((unsigned)(((m) >> 9) & 0x1))
#define IOMFB_TAG(m)      ((unsigned)(((m) >> 10) & 0x3f))
#define IOMFB_HDR(m)      ((uint16_t)(m))

/* class-2 payload split (0xa0ce65c-0xa0ce688) */
#define IOMFB_RPC_OFF(m)  ((uint32_t)(((m) >> 16) & 0xffff))
#define IOMFB_RPC_SIZE(m) ((uint32_t)(((m) >> 32) & 0xffff))

/*
 * Shared-heap geometry, all read out of link_state_init (fcn.fffffff00a0cf5b8)
 * rather than assumed. See section 5 of the header comment.
 *
 *   0x00000 + t*0x8000   AP's own request window for tag t   (slot+0x08)
 *   0x20000 + t*0x8000   inbound slot's TX window            (slot+0x08)
 *   0x40000 + t*0x8000   inbound request window for tag t    (slot+0x18)
 *   0x60000 + t*0x8000   AP's own slot RX window             (slot+0x18)
 *
 * IOMFB_TAGS is 4 because the slot lookup REQUIREs tag < 4 (0xa0d033c);
 * a fifth outstanding call in one direction is a guest panic, not a wrap.
 */
#define IOMFB_TAGS        4
#define IOMFB_WINDOW      0x8000u       /* mov w14, #0x8000 @ 0xa0cf650 */
#define IOMFB_AP_REQ_BASE 0x00000u      /* str x16,[x17,#8]  @ 0xa0cf664 */
#define IOMFB_CB_TX_BASE  0x20000u      /* str x13,[x17,#8]  @ 0xa0cf6a0 */
#define IOMFB_CB_REQ_BASE 0x40000u      /* str x15,[x17,#0x18] @ 0xa0cf6cc */
#define IOMFB_AP_RX_BASE  0x60000u      /* str x0,[x17,#0x18] @ 0xa0cf67c */

/* At most 64 sparse rows (1024 input bytes) are printed per unique request. */
#define IOMFB_TRACE_ROW_BYTES 16u
#define IOMFB_TRACE_ROWS_MAX  64u

/*
 * crc32(0, {0xd3,0,0,0}, 4). See step 2 above: the AP recomputes this from
 * its own __DATA on every class-1 message and compares it 32-bit, so it is a
 * build constant, not a secret. It is *this* kernelcache's value.
 */
#define IOMFB_FW_HASH 0x15A5C96BU

/* Request header in the shared heap (0xa0ce608-0xa0ce614). */
typedef struct QEMU_PACKED {
    uint32_t name;      /* FourCC, stored little-endian, printed big-endian */
    uint32_t in_len;
    uint32_t out_len;
} IOMFBRpcHdr;

#define IOMFB_SWAP_QUEUE_SIZE 8

struct DarwinIOMFB {
    DeviceState *asc;
    DeviceState *dart;
    unsigned sid;
    unsigned level;
    bool debug;
    bool rpc_trace;

    /*
     * Structured DCP event trace (DARWIN_DCP_TRACE=/path). One CSV row per
     * RPC request ('R') and completion ('C'): guest-virtual timestamp (ns),
     * FourCC, endpoint, in/out lengths, note. This complements the stderr
     * logs; it never replaces them. The file is opened append-mode and a
     * header row is written when the file is new or empty.
     */
    FILE *dcp_event_fp;
    uint64_t dcp_event_n;

    /* The AP's shared heap, from the class-0/subkind-1 announce. */
    bool heap_known;
    uint64_t heap_dva;

    bool dma_warned;    /* one DART complaint per boot, not one per message */
    uint64_t rpcs;

    /*
     * Exact request signatures seen by DARWIN_DCP_IOMFB_RPC_TRACE. Keys are
     * {RPC header,input bytes}; values are occurrence counters. Exact keys
     * avoid a digest collision hiding a genuinely new body. The table lives
     * for one VM, so a repeat can retain its compact context line without
     * reproducing a potentially large dump on every frame.
     */
    GHashTable *rpc_trace_seen; /* GBytes* -> uint64_t* */

    /*
     * Experiment harness, DARWIN_DCP_IOMFB_OUT. The default answer to every
     * RPC is "status 0, output all zeroes" (see the header comment): honest,
     * but often not what the driver wants to hear. This lets a probe try a
     * different canned answer without a rebuild, so the boot log can say
     * which one moves the guest forward, eg.
     *
     *   DARWIN_DCP_IOMFB_OUT='A401=01,A410=0100'
     *
     * Bytes are hex, little-endian on the wire (they are copied verbatim
     * into the output region), truncated or zero-padded to out_len. Nothing
     * here is derived from firmware; every entry is a hypothesis under test
     * and none of them is a default.
     */
    GHashTable *out_override;   /* char* FourCC -> GByteArray* */

    /*
     * The outbound (D-series) experiment harness, DARWIN_DCP_IOMFB_CB. See
     * section 5 of the header comment for the transport and
     * docs/re/iomfb-dseries.md for the 139 names the AP will accept.
     *
     * cb_script is a list of callback or AP-RPC barrier items in execution
     * order. One callback is outstanding at a time (cb_busy), because the AP
     * correlates purely by (ack, tag) and we only ever use tag 0, so a second
     * in flight would be indistinguishable from the first. A barrier never
     * changes cb_busy or emits a mailbox word; it only holds cb_next until a
     * later matching AP RPC has been answered. cb_after names the inbound RPC
     * whose completion starts the script, or is empty to start right after
     * the class-1 init ack.
     */
    GArray *cb_script;
    unsigned cb_next;
    bool cb_busy;
    bool cb_started;
    bool cb_flag9;          /* mirror the AP's own bit 9; see iomfb_callback_send */
    char *cb_after;
    uint64_t cb_sent;

    /* Opt-in native D594 completion of accepted A408s. IDs come from the
     * actual request; completion state is separate from the boot script. */
    bool swap_enabled;
    bool scanout_enabled;
    uint32_t swap_ids[IOMFB_SWAP_QUEUE_SIZE];
    uint32_t swap_head, swap_count;
    bool swap_active, swap_failed;
    /* A408 remains outstanding until its same-slot D594 returns. */
    bool swap_nested[IOMFB_TAGS];
    uint32_t swap_nested_ids[IOMFB_TAGS];

    /*
     * Opt-in native one-shot D575 hot-plug-detect producer
     * (DARWIN_DCP_IOMFB_HOTPLUG). Armed when the first A389 display
     * query is answered (early; see above); the delay then gives WindowServer's bring-up
     * time to register its kernel hot-plug listeners before the event
     * lands (the kernel also pends the event if no listener has
     * registered yet, so landing early is not fatal). sent/active
     * track the single attempt; a failed send or a non-zero completion
     * status latches hotplug_failed instead of retrying.
     */
    bool hotplug_enabled;
    unsigned hotplug_delay_sec;
    bool hotplug_armed;
    bool hotplug_sent;
    bool hotplug_active;
    bool hotplug_failed;
    uint8_t hotplug_ep;
    QEMUTimer *hotplug_timer;
};

static int darwin_iomfb_post_load(void *opaque, int version_id)
{
    DarwinIOMFB *m = opaque;

    if ((m->cb_next || m->cb_started ||
         (m->cb_busy && !m->swap_active && !m->hotplug_active)) &&
        !m->cb_script && !m->hotplug_enabled) {
        return -EINVAL;
    }
    if (m->cb_script && m->cb_next > m->cb_script->len) {
        return -EINVAL;
    }
    if (m->heap_known && !m->heap_dva) {
        return -EINVAL;
    }
    return 0;
}

static bool iomfb_swap_state_needed(void *opaque)
{
    DarwinIOMFB *m = opaque;
    return m->swap_count || m->swap_active || m->swap_failed;
}

static int iomfb_swap_post_load(void *opaque, int version_id)
{
    DarwinIOMFB *m = opaque;
    if (!m->swap_enabled || m->swap_count > IOMFB_SWAP_QUEUE_SIZE ||
        m->swap_head >= IOMFB_SWAP_QUEUE_SIZE ||
        (m->swap_active && (!m->cb_busy || !m->swap_count || m->swap_failed))) {
        return -EINVAL;
    }
    return 0;
}

static const VMStateDescription vmstate_iomfb_swap = {
    .name = "darwin-iomfb/swap-completion",
    .version_id = 1,
    .minimum_version_id = 1,
    .needed = iomfb_swap_state_needed,
    .post_load = iomfb_swap_post_load,
    .fields = (const VMStateField[]) {
        VMSTATE_UINT32_ARRAY(swap_ids, DarwinIOMFB, IOMFB_SWAP_QUEUE_SIZE),
        VMSTATE_UINT32(swap_head, DarwinIOMFB),
        VMSTATE_UINT32(swap_count, DarwinIOMFB),
        VMSTATE_BOOL(swap_active, DarwinIOMFB),
        VMSTATE_BOOL(swap_failed, DarwinIOMFB),
        VMSTATE_END_OF_LIST()
    },
};

static bool iomfb_nested_state_needed(void *opaque)
{
    DarwinIOMFB *m = opaque;
    for (unsigned t = 0; t < IOMFB_TAGS; t++) {
        if (m->swap_nested[t]) {
            return true;
        }
    }
    return false;
}

static int iomfb_nested_post_load(void *opaque, int version_id)
{
    DarwinIOMFB *m = opaque;
    return m->swap_enabled && m->heap_known ? 0 : -EINVAL;
}

/* Separate optional state keeps pre-fix checkpoints readable, including an
 * old asynchronous D594 that must still retire through its ack-1 slot. */
static const VMStateDescription vmstate_iomfb_nested = {
    .name = "darwin-iomfb/nested-swap",
    .version_id = 1,
    .minimum_version_id = 1,
    .needed = iomfb_nested_state_needed,
    .post_load = iomfb_nested_post_load,
    .fields = (const VMStateField[]) {
        VMSTATE_BOOL_ARRAY(swap_nested, DarwinIOMFB, IOMFB_TAGS),
        VMSTATE_UINT32_ARRAY(swap_nested_ids, DarwinIOMFB, IOMFB_TAGS),
        VMSTATE_END_OF_LIST()
    },
};

static void iomfb_hotplug_timer_cb(void *opaque);

static bool iomfb_hotplug_state_needed(void *opaque)
{
    DarwinIOMFB *m = opaque;
    return m->hotplug_armed || m->hotplug_sent || m->hotplug_active ||
           m->hotplug_failed;
}

static int iomfb_hotplug_post_load(void *opaque, int version_id)
{
    DarwinIOMFB *m = opaque;
    if (!m->hotplug_enabled || (m->hotplug_active && !m->cb_busy)) {
        return -EINVAL;
    }
    if (m->hotplug_armed && !m->hotplug_sent && !m->hotplug_failed) {
        /*
         * The QEMUTimer is not part of the migrated state, so a snapshot
         * restore would otherwise leave the one-shot producer permanently
         * silent. Re-create and re-arm it; the D575 then fires
         * hotplug_delay_sec after the restore, exactly as on a fresh boot.
         */
        m->hotplug_timer = timer_new_ms(QEMU_CLOCK_VIRTUAL,
                                        iomfb_hotplug_timer_cb, m);
        timer_mod(m->hotplug_timer,
                  qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) +
                  (int64_t)m->hotplug_delay_sec * 1000);
        fprintf(stderr, "iomfb: D575 hot-plug-detect timer re-armed post-load"
                " (+%u s)\n", m->hotplug_delay_sec);
    }
    return 0;
}

static const VMStateDescription vmstate_iomfb_hotplug = {
    .name = "darwin-iomfb/hotplug-detect",
    .version_id = 1,
    .minimum_version_id = 1,
    .needed = iomfb_hotplug_state_needed,
    .post_load = iomfb_hotplug_post_load,
    .fields = (const VMStateField[]) {
        VMSTATE_BOOL(hotplug_armed, DarwinIOMFB),
        VMSTATE_BOOL(hotplug_sent, DarwinIOMFB),
        VMSTATE_BOOL(hotplug_active, DarwinIOMFB),
        VMSTATE_BOOL(hotplug_failed, DarwinIOMFB),
        VMSTATE_UINT8(hotplug_ep, DarwinIOMFB),
        VMSTATE_END_OF_LIST()
    },
};

static const VMStateDescription vmstate_darwin_iomfb = {
    .name = "darwin-iomfb",
    .version_id = 1,
    .minimum_version_id = 1,
    .post_load = darwin_iomfb_post_load,
    .fields = (const VMStateField[]) {
        VMSTATE_UINT32_EQUAL(sid, DarwinIOMFB),
        VMSTATE_UINT32_EQUAL(level, DarwinIOMFB),
        VMSTATE_BOOL(heap_known, DarwinIOMFB),
        VMSTATE_UINT64(heap_dva, DarwinIOMFB),
        VMSTATE_UINT64(rpcs, DarwinIOMFB),
        VMSTATE_UINT32(cb_next, DarwinIOMFB),
        VMSTATE_BOOL(cb_busy, DarwinIOMFB),
        VMSTATE_BOOL(cb_started, DarwinIOMFB),
        VMSTATE_BOOL(cb_flag9, DarwinIOMFB),
        VMSTATE_UINT64(cb_sent, DarwinIOMFB),
        VMSTATE_END_OF_LIST()
    },
    .subsections = (const VMStateDescription * const[]) {
        &vmstate_iomfb_swap,
        &vmstate_iomfb_nested,
        &vmstate_iomfb_hotplug,
        NULL
    },
};

void darwin_iomfb_register_vmstate(DarwinIOMFB *m, unsigned instance_id)
{
    int ret = vmstate_register(NULL, instance_id, &vmstate_darwin_iomfb, m);

    g_assert(ret == 0);
}

/* One scripted outbound callback, or an @NAME AP-RPC barrier. */
typedef struct {
    char name[5];
    bool barrier;
    uint32_t name_be;       /* the u32 as it goes into the heap */
    GByteArray *in;         /* input bytes, verbatim */
    uint32_t out_len;
} IOMFBCallback;

/* ------------------------------------------------------------------ DMA -- */

/*
 * Read/write guest memory the way the real DCP would: through its DART, with
 * the stream id the device tree gives /arm-io/dcp. Re-translates on every 4K
 * boundary because darwin_dart_translate() maps a single address and 4K
 * divides every Apple DART granule. Identical in shape to afk_dma() in
 * darwin_afk.c; kept separate only because this file has no ring state.
 *
 * A failure is reported and propagated, never papered over -- writing to a
 * wrong physical address would corrupt the guest silently.
 */
static bool iomfb_dma(DarwinIOMFB *m, uint64_t dva, void *buf, uint32_t len,
                      bool is_write) {
    uint8_t *p = buf;

    if (!m->dart) {
        if (!m->dma_warned) {
            m->dma_warned = true;
            fprintf(stderr, "iomfb: no DART; cannot reach the RPC heap at dva 0x%" PRIx64 "\n",
                    dva);
        }
        return false;
    }
    while (len) {
        uint64_t pa;
        if (!darwin_dart_translate(m->dart, m->sid, dva, &pa)) {
            if (!m->dma_warned) {
                m->dma_warned = true;
                fprintf(stderr, "iomfb: DART sid %u has no mapping for dva 0x%" PRIx64
                        " (%s)\n", m->sid, dva, is_write ? "write" : "read");
                darwin_dart_dump_sid(m->dart, m->sid);
            }
            return false;
        }
        uint32_t chunk = 0x1000 - (uint32_t)(dva & 0xfff);
        if (chunk > len) chunk = len;
        if (address_space_rw(&address_space_memory, pa, MEMTXATTRS_UNSPECIFIED,
                             p, chunk, is_write) != MEMTX_OK) {
            fprintf(stderr, "iomfb: guest memory access failed at pa 0x%" PRIx64 "\n", pa);
            return false;
        }
        dva += chunk;
        p += chunk;
        len -= chunk;
    }
    return true;
}

/* Pixel DMA is disp0/sid0, not the RPC heap's dcp/sid23. Proven by
 * a 1 MiB byte match against native IOSurface pixels in VISIBLE_R6. */
static bool iomfb_scanout(const uint8_t *input, uint32_t len)
{
    DarwinIOMFBSurface surface;
    DeviceState *dart = darwin_dart_find("dart-disp0");
    g_autofree uint8_t *pixels = NULL;
    if (!dart || !darwin_iomfb_swap_surface(input, len, &surface)) {
        fprintf(stderr, "iomfb: scanout unsupported primary BGRA profile\n");
        return false;
    }
    pixels = g_malloc(surface.size);
    for (uint32_t off = 0; off < surface.size; ) {
        uint64_t dva = surface.dva + off, pa;
        uint32_t chunk = MIN(0x1000 - (dva & 0xfff), surface.size - off);
        if (!darwin_dart_translate(dart, 0, dva, &pa) ||
            address_space_read(&address_space_memory, pa,
                               MEMTXATTRS_UNSPECIFIED, pixels + off,
                               chunk) != MEMTX_OK) {
            fprintf(stderr, "iomfb: scanout DMA failed at 0x%" PRIx64 "\n", dva);
            return false;
        }
        off += chunk;
    }
    if (!darwin_fb_present_bgra(pixels, surface.width, surface.height,
                                surface.stride)) {
        fprintf(stderr, "iomfb: scanout console geometry mismatch\n");
        return false;
    }
    fprintf(stderr, "iomfb: presented %ux%u BGRA, stride %u, dva 0x%" PRIx64 "\n",
            surface.width, surface.height, surface.stride, surface.dva);
    return true;
}

static void iomfb_hexdump(const char *what, const uint8_t *p, uint32_t len) {
    if (!len) {
        fprintf(stderr, "iomfb:   %s: (empty)\n", what);
        return;
    }
    for (uint32_t i = 0; i < len; i += 16) {
        char line[3 * 16 + 1];
        int n = 0;
        for (uint32_t j = i; j < len && j < i + 16; j++) {
            n += snprintf(line + n, sizeof(line) - n, "%02x ", p[j]);
        }
        fprintf(stderr, "iomfb:   %s +%04x: %s\n", what, i, line);
    }
}

/*
 * Print only 16-byte input rows containing a non-zero byte. For a large,
 * dense request retain both ends (32 rows each): surface descriptors tend to
 * live near the front while address arrays can live near the tail. The cap
 * and selection are deterministic, and the summary says exactly what was
 * omitted so the trace cannot be mistaken for a complete body.
 */
static void iomfb_trace_sparse_input(const uint8_t *p, uint32_t len)
{
    g_autoptr(GArray) rows = g_array_new(FALSE, FALSE, sizeof(uint32_t));
    uint32_t nonzero_bytes = 0;

    for (uint32_t off = 0; off < len; off += IOMFB_TRACE_ROW_BYTES) {
        uint32_t end = MIN(len, off + IOMFB_TRACE_ROW_BYTES);
        bool any = false;

        for (uint32_t i = off; i < end; i++) {
            if (p[i]) {
                any = true;
                nonzero_bytes++;
            }
        }
        if (any) {
            g_array_append_val(rows, off);
        }
    }

    uint32_t shown = MIN(rows->len, IOMFB_TRACE_ROWS_MAX);
    fprintf(stderr, "iomfb: TRACE   input len 0x%x nonzero-bytes %u "
            "nonzero-rows %u shown %u omitted %u\n",
            len, nonzero_bytes, rows->len, shown, rows->len - shown);

    for (uint32_t n = 0; n < shown; n++) {
        uint32_t row_index;

        if (rows->len <= IOMFB_TRACE_ROWS_MAX ||
            n < IOMFB_TRACE_ROWS_MAX / 2) {
            row_index = n;
        } else {
            row_index = rows->len - (IOMFB_TRACE_ROWS_MAX - n);
        }

        uint32_t off = g_array_index(rows, uint32_t, row_index);
        uint32_t end = MIN(len, off + IOMFB_TRACE_ROW_BYTES);
        char line[3 * IOMFB_TRACE_ROW_BYTES + 1];
        int pos = 0;

        for (uint32_t i = off; i < end; i++) {
            pos += snprintf(line + pos, sizeof(line) - pos, "%02x ", p[i]);
        }
        fprintf(stderr, "iomfb: TRACE   in-nz +0x%04x: %s\n", off, line);
    }
}

/*
 * Return this exact request body's occurrence count. A complete bytewise key
 * is used instead of a hash-only key so tracing never suppresses a distinct
 * layout because of a collision. The caller still emits one context line for
 * every RPC; only duplicate body dumps are suppressed.
 */
static uint64_t iomfb_trace_occurrence(DarwinIOMFB *m,
                                       const IOMFBRpcHdr *h,
                                       const uint8_t *input,
                                       uint32_t input_len)
{
    GByteArray *key_bytes = g_byte_array_sized_new(sizeof(*h) + input_len);
    g_byte_array_append(key_bytes, (const uint8_t *)h, sizeof(*h));
    if (input_len) {
        g_byte_array_append(key_bytes, input, input_len);
    }
    GBytes *key = g_byte_array_free_to_bytes(key_bytes);
    uint64_t *count = g_hash_table_lookup(m->rpc_trace_seen, key);

    if (count) {
        (*count)++;
        g_bytes_unref(key);
        return *count;
    }

    count = g_new(uint64_t, 1);
    *count = 1;
    g_hash_table_insert(m->rpc_trace_seen, key, count);
    return 1;
}

/*
 * Level 4: the canned RPC answers that a *measurement* showed advance the
 * guest. Each entry names the call site that reads the value and what the
 * boot log did with and without it. Nothing here is a semantic model of the
 * method -- it is a hypothesis that survived a boot, which is why it is a
 * separate level rather than the level-3 default.
 *
 * A401  IOMobileFramebufferAP::start() calls it through vtable slot +0x970
 *       at 0xfffffff00a0b5fe4 -- the very next thing after the log line our
 *       boot ends on, "%s: fRackDebugSwapWaitTimeoutSec = %d"
 *       (0xfffffff00798f021) -- and branches on bit 0 of the result at
 *       0xa0b5fec (`tbz w0, 0, 0xa0b6154`). True publishes an
 *       "IOMFB Debug Info" (0xfffffff00798f047) property; false stores 0 at
 *       this+0x260 and skips it (0xa0b6154). The stub itself is at
 *       0xfffffff00a0c8a80: in_len 0, out_len 4, and it returns
 *       `out[0] & 1`, so it is a bool.
 *
 *       Measured, io=0x1f, otherwise identical boots:
 *         out=00 -> "AppleCLCD2[...]::start took 596 ms" and nothing else;
 *                   the driver then runs IOMFB_POWER_DART set_power_state
 *                   powerState=0 and no AppleCLCD2 service is registered.
 *         out=01 -> "Registering: ../disp0@0/AppleCLCD2" followed by
 *                   "AppleCLCD2[...]::start took 657 ms", and two further
 *                   RPCs flow (A465 with in {0x800,0x20}, A353 out 8).
 */
typedef struct { const char *name; const char *hex; } IOMFBCannedOut;
static const IOMFBCannedOut iomfb_level4[] = {
    { "A401", "01" },
};

static void iomfb_free_bytes(gpointer p) {
    g_byte_array_unref((GByteArray *)p);
}

/*
 * Parse DARWIN_DCP_IOMFB_OUT into m->out_override. Format is a comma or
 * space separated list of NAME=HEXBYTES, eg. "A401=01,A500=".  Malformed
 * entries are reported and skipped rather than silently ignored.
 */
static void iomfb_parse_overrides(DarwinIOMFB *m, const char *spec) {
    g_auto(GStrv) items = g_strsplit_set(spec, ", ", -1);

    for (char **it = items; it && *it; it++) {
        if (!**it) continue;
        char *eq = strchr(*it, '=');
        if (!eq || eq - *it != 4) {
            fprintf(stderr, "iomfb: DARWIN_DCP_IOMFB_OUT: cannot parse \"%s\" "
                    "(want NAME=HEXBYTES, NAME exactly 4 chars); skipped\n", *it);
            continue;
        }
        *eq = 0;
        const char *hex = eq + 1;
        if (strlen(hex) & 1) {
            fprintf(stderr, "iomfb: DARWIN_DCP_IOMFB_OUT: odd hex digit count for %s; "
                    "skipped\n", *it);
            continue;
        }
        GByteArray *bytes = g_byte_array_new();
        bool ok = true;
        for (const char *q = hex; *q; q += 2) {
            char pair[3] = { q[0], q[1], 0 };
            char *end = NULL;
            unsigned long v = strtoul(pair, &end, 16);
            if (end != pair + 2) { ok = false; break; }
            uint8_t b = (uint8_t)v;
            g_byte_array_append(bytes, &b, 1);
        }
        if (!ok) {
            fprintf(stderr, "iomfb: DARWIN_DCP_IOMFB_OUT: bad hex for %s; skipped\n", *it);
            g_byte_array_unref(bytes);
            continue;
        }
        if (!m->out_override) {
            m->out_override = g_hash_table_new_full(g_str_hash, g_str_equal, g_free,
                                                    iomfb_free_bytes);
        }
        g_hash_table_insert(m->out_override, g_strdup(*it), bytes);
        fprintf(stderr, "iomfb: PROBE override: %s returns %u byte(s) 0x%s\n",
                *it, bytes->len, hex);
    }
}

/* -------------------------------------------- structured event trace -- */

/*
 * Structured DCP event trace, DARWIN_DCP_TRACE=/path. One CSV row per event:
 *   t_ns,dir,fourcc,ep,in_len,out_len,note
 * t_ns is QEMU_CLOCK_VIRTUAL (guest time) in nanoseconds. dir is R (AP->DCP
 * RPC request), C (DCP->AP RPC completion), or M (other mailbox control
 * message). fourcc is the 4-char RPC name, "-" for control messages. note
 * carries the completion answer mode ("zeroed", "PROBE override",
 * "built-in A489") or "nested" for callback-context requests. Buffered
 * (64 KiB) with a flush every 1024 events so a crashed guest still leaves a
 * usable trace.
 */
static void iomfb_dcp_event(DarwinIOMFB *m, char dir, const char *fourcc,
                            uint8_t ep, uint32_t in_len, uint32_t out_len,
                            const char *note)
{
    FILE *fp = m->dcp_event_fp;
    if (!fp) {
        return;
    }
    fprintf(fp, "%" PRIu64 ",%c,%s,%u,%u,%u,%s\n",
            (uint64_t)qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL),
            dir, fourcc, ep, in_len, out_len, note ? note : "");
    if ((++m->dcp_event_n & 1023) == 0) {
        fflush(fp);
    }
}

static void iomfb_dcp_event_open(DarwinIOMFB *m, const char *path)
{
    FILE *fp = fopen(path, "a");
    if (!fp) {
        fprintf(stderr, "iomfb: DARWIN_DCP_TRACE: cannot open '%s': %s; "
                "structured trace disabled\n", path, strerror(errno));
        return;
    }
    if (ftell(fp) == 0) {
        fprintf(fp, "t_ns,dir,fourcc,ep,in_len,out_len,note\n");
    }
    setvbuf(fp, NULL, _IOFBF, 64 * 1024);
    m->dcp_event_fp = fp;
    fprintf(stderr, "iomfb: structured DCP event trace enabled: %s\n", path);
}

/* -------------------------------------------------------------- sending -- */

static void iomfb_send(DarwinIOMFB *m, uint8_t ep, uint64_t msg, const char *what) {
    fprintf(stderr, "iomfb: IOP -> AP ep 0x%02x 0x%016" PRIx64 "  (%s)\n", ep, msg, what);
    darwin_asc_send(m->asc, ep, msg);
}

/* ------------------------------------------------- outbound callbacks (D) -- */

/*
 * Issue one D-series callback: build the request in the inbound window and
 * send the class-2 / subkind-0 message that points at it.
 *
 * Every field here has a source in section 5 of the header comment:
 *
 *   window   heap + 0x40000 + tag*0x8000        link_state_init 0xa0cf6cc
 *   layout   u32 name, u32 in_len, u32 out_len, in[], out[]
 *                                               rpc_callee_gated 0xa0cf0d8-0xa0cf100
 *   size     0xc + in_len + out_len, and the AP rejects anything else
 *                                               0xa0cf0dc-0xa0cf0fc
 *   header   class 2, subkind 0, bit 8 SET      0xa0d0328-0xa0d0334, 0xa0cf5e8
 *   payload  bits[31:16] offset, bits[47:32] size
 *                                               rpc_caller_gated 0xa0ce65c-0xa0ce688
 *
 * Bit 9 is left clear. The AP sets it in its own requests and
 * rpc_callee_gated echoes it back untouched (its reply mask 0xff3e preserves
 * it) but never tests it, so there is nothing to model; a logged no-op by
 * omission rather than a guessed value.
 *
 * The offset within the window is always 0: we have exactly one call
 * outstanding, so there is nothing to pack around.
 */
static bool iomfb_callback_send_slot(DarwinIOMFB *m, uint8_t ep,
                                     const IOMFBCallback *cb,
                                     unsigned ack, unsigned tag)
{
    uint32_t base = ack ? IOMFB_CB_REQ_BASE : IOMFB_AP_RX_BASE;
    uint32_t in_len = cb->in ? cb->in->len : 0;
    uint32_t size = (uint32_t)sizeof(IOMFBRpcHdr) + in_len + cb->out_len;

    if (!m->heap_known) {
        fprintf(stderr, "iomfb: cannot send callback '%s': the AP has not "
                "announced its heap yet\n", cb->name);
        return false;
    }
    if (size > IOMFB_WINDOW) {
        fprintf(stderr, "iomfb: callback '%s' needs 0x%x bytes but a window is "
                "only 0x%x; not sent\n", cb->name, size, IOMFB_WINDOW);
        return false;
    }

    uint64_t dva = m->heap_dva + base + (uint64_t)tag * IOMFB_WINDOW;
    g_autofree uint8_t *buf = g_malloc0(size);
    IOMFBRpcHdr h = { .name = cb->name_be, .in_len = in_len,
                      .out_len = cb->out_len };
    memcpy(buf, &h, sizeof(h));
    if (in_len) {
        memcpy(buf + sizeof(h), cb->in->data, in_len);
    }
    if (!iomfb_dma(m, dva, buf, size, true)) {
        fprintf(stderr, "iomfb: callback '%s': could not write the request at "
                "dva 0x%" PRIx64 "\n", cb->name, dva);
        return false;
    }

    m->cb_sent++;
    fprintf(stderr, "iomfb: ep 0x%02x callback #%" PRIu64 " '%s' (0x%08x) in %u "
            "out %u -> heap+0x%x (tag %u) size 0x%x\n",
            ep, m->cb_sent, cb->name, cb->name_be, in_len, cb->out_len,
            base + tag * IOMFB_WINDOW, tag, size);
    if (m->debug && in_len) {
        iomfb_hexdump("cb in", buf + sizeof(h), in_len);
    }

    /*
     * Bit 9. rpc_caller_gated sets it on every request the AP sends
     * (`bfi x25, x23, #9, #1` @ 0xa0ce668; every observed A-series message is
     * 0x...202, not 0x...002) and link_send_message preserves it verbatim
     * (`val & 0x2ff` @ 0xa0ced0c). rpc_callee_gated never reads it, so its
     * MEANING is not derived -- but "send what the peer sends" is a better
     * default than "send what we happen to find simplest", and this is the
     * only field in which our request differed from the AP's own.
     * DARWIN_DCP_IOMFB_CB_FLAG9=0 puts it back, so the difference stays
     * measurable rather than baked in.
     */
    uint64_t msg = 0x02ULL                       /* class 2, subkind 0      */
                 | ((uint64_t)ack << 8)
                 | ((uint64_t)(m->cb_flag9 ? 1 : 0) << 9)
                 | ((uint64_t)tag << 10)
                 | (0ULL << 16)                  /* offset within the window */
                 | ((uint64_t)size << 32);
    char what[96];
    snprintf(what, sizeof(what), "class-2 callback '%s'", cb->name);
    iomfb_send(m, ep, msg, what);
    return true;
}

static bool iomfb_callback_send(DarwinIOMFB *m, uint8_t ep, const IOMFBCallback *cb)
{
    if (!iomfb_callback_send_slot(m, ep, cb, 1, 0)) {
        return false;
    }
    m->cb_busy = true;
    return true;
}

/* rpc_caller_gated handles incoming requests itself while awaiting a reply
 * (24A5430a a0ce750-a0ce770). Use the A408 caller's ack-0 RX window, whose
 * base is assigned at a0cf66c-a0cf67c. The native queue entry already exists
 * before A408 (a0c3730 -> a0c4500), so D594 may retire it here.
 *
 * Replying first and sending D594 on a separate workloop permits a power
 * lock inversion: SwapEnd owns IORecursiveLock while a0cf708 drains that
 * workloop, and D594 surface release needs the same lock in a0d5b14.
 * See docs/re/display-completion-deadlock.md for the measured cycle. */
static bool iomfb_swap_send_nested(DarwinIOMFB *m, uint8_t ep, unsigned tag,
                                   uint32_t id)
{
    uint8_t input[DARWIN_IOMFB_SWAP_COMPLETION_SIZE];
    IOMFBCallback cb = { .name = "D594", .name_be = 0x44353934 };
    bool sent;

    if (m->swap_nested[tag]) {
        fprintf(stderr, "iomfb: recursive A408 on occupied tag %u; stopped\n", tag);
        return false;
    }
    darwin_iomfb_swap_completion(input, id);
    cb.in = g_byte_array_new_take(g_memdup2(input, sizeof(input)), sizeof(input));
    sent = iomfb_callback_send_slot(m, ep, &cb, 0, tag);
    g_byte_array_unref(cb.in);
    if (sent) {
        m->swap_nested[tag] = true;
        m->swap_nested_ids[tag] = id;
        fprintf(stderr, "iomfb: swap id %u D594 nested on tag %u; A408 pending\n",
                id, tag);
    }
    return sent;
}

static void iomfb_swap_pump(DarwinIOMFB *m, uint8_t ep)
{
    uint8_t input[DARWIN_IOMFB_SWAP_COMPLETION_SIZE];
    IOMFBCallback cb = { .name = "D594", .name_be = 0x44353934 };

    if (!m->swap_enabled || m->swap_failed || m->cb_busy || !m->swap_count) {
        return;
    }
    darwin_iomfb_swap_completion(input, m->swap_ids[m->swap_head]);
    cb.in = g_byte_array_new_take(g_memdup2(input, sizeof(input)), sizeof(input));
    m->swap_active = iomfb_callback_send(m, ep, &cb);
    g_byte_array_unref(cb.in);
    if (!m->swap_active) {
        /* Retain the ID for inspection rather than silently losing a frame. */
        m->swap_failed = true;
    }
    fprintf(stderr, "iomfb: swap id %u D594 %s, queued %u\n",
            m->swap_ids[m->swap_head], m->swap_active ? "sent" : "send failed",
            m->swap_count);
}

static void iomfb_swap_enqueue(DarwinIOMFB *m, const uint8_t *input,
                              uint32_t in_len, uint32_t out_len)
{
    uint32_t id;
    if (!darwin_iomfb_swap_id(input, in_len, out_len, &id)) {
        fprintf(stderr, "iomfb: unsupported A408 completion shape; no D594 queued\n");
        return;
    }
    for (uint32_t i = 0; i < m->swap_count; i++) {
        if (m->swap_ids[(m->swap_head + i) % IOMFB_SWAP_QUEUE_SIZE] == id) {
            fprintf(stderr, "iomfb: swap id %u already queued; no duplicate D594\n", id);
            return;
        }
    }
    if (m->swap_count == IOMFB_SWAP_QUEUE_SIZE) {
        m->swap_failed = true;
        fprintf(stderr, "iomfb: swap completion queue full at id %u; stopped\n", id);
        return;
    }
    m->swap_ids[(m->swap_head + m->swap_count) % IOMFB_SWAP_QUEUE_SIZE] = id;
    m->swap_count++;
}

/*
 * The D575 hot-plug-detect input, as the guest handler declares it
 * (0xfffffff00a1964e4 in the 24A446 kernelcache): a u64 event code at
 * +0 (1 = display attached), the trailing bool at +0x53, and the
 * optional-structure flag at +0x54. Setting the flag makes the handler
 * pass NULL for the optional IOMFB_TiledDisplayInfo argument, which
 * the hot-plug target does not read (hotPlug_notify_gated consumes
 * only the event and the bool), so the AP never dereferences it.
 */
#define IOMFB_HOTPLUG_IN_LEN  0x58
#define IOMFB_HOTPLUG_OUT_LEN 0x4c

static void iomfb_hotplug_try_send(DarwinIOMFB *m)
{
    uint8_t input[IOMFB_HOTPLUG_IN_LEN] = { 0 };
    IOMFBCallback cb = { .name = "D575", .name_be = 0x44353735,
                         .out_len = IOMFB_HOTPLUG_OUT_LEN };

    if (!m->hotplug_enabled || !m->hotplug_armed || m->hotplug_sent ||
        m->hotplug_failed || m->cb_busy) {
        return;
    }
    if (!m->heap_known) {
        m->hotplug_failed = true;
        fprintf(stderr, "iomfb: D575 hot-plug-detect: the AP has not "
                "announced its heap; producer stopped\n");
        return;
    }

    input[0] = 1;               /* event u64 at +0: display attached */
    input[0x53] = 1;            /* trailing bool at +0x53 */
    input[0x54] = 1;            /* at +0x54: no optional structure */
    cb.in = g_byte_array_new_take(g_memdup2(input, sizeof(input)),
                                  sizeof(input));
    m->hotplug_sent = true;
    m->hotplug_active = iomfb_callback_send(m, m->hotplug_ep, &cb);
    g_byte_array_unref(cb.in);
    if (!m->hotplug_active) {
        m->hotplug_failed = true;
        fprintf(stderr, "iomfb: D575 hot-plug-detect could not be sent; "
                "producer stopped\n");
        return;
    }
    fprintf(stderr, "iomfb: D575 hot-plug-detect sent (event 1, bool 1, "
            "no optional structure)\n");
}

static void iomfb_hotplug_timer_cb(void *opaque)
{
    DarwinIOMFB *m = opaque;

    fprintf(stderr, "iomfb: hot-plug-detect delay elapsed; sending D575\n");
    iomfb_hotplug_try_send(m);
    if (!m->hotplug_sent && !m->hotplug_failed) {
        /* The callback slot was busy; retry. */
        timer_mod(m->hotplug_timer,
                  qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + 2000);
    }
}

/* Send the next scripted callback, if any and if none is outstanding. */
static void iomfb_callback_pump(DarwinIOMFB *m, uint8_t ep)
{
    while (!m->cb_busy && m->cb_script && m->cb_next < m->cb_script->len) {
        const IOMFBCallback *cb =
            &g_array_index(m->cb_script, IOMFBCallback, m->cb_next);
        if (cb->barrier) {
            fprintf(stderr, "iomfb: callback script waiting at @%s for a "
                    "later AP RPC\n", cb->name);
            return;
        }
        m->cb_next++;
        if (iomfb_callback_send(m, ep, cb)) {
            return;                     /* wait for the completion */
        }
        /* Could not send it at all: move on rather than stalling the script. */
    }
    iomfb_swap_pump(m, ep);
}

/*
 * Release the current @NAME barrier after the matching AP RPC has completed.
 * This runs after our class-2 completion is sent, so "observed" means the AP
 * caller has received the same answer it would have received without a
 * script. The barrier is deliberately independent of cb_busy: it sends no
 * callback, consumes no tag, and cannot masquerade as callback completion.
 */
static void iomfb_callback_barrier(DarwinIOMFB *m, uint8_t ep,
                                   const char name[5])
{
    if (!m->cb_started || m->cb_busy || !m->cb_script ||
        m->cb_next >= m->cb_script->len) {
        return;
    }

    const IOMFBCallback *item =
        &g_array_index(m->cb_script, IOMFBCallback, m->cb_next);
    if (!item->barrier || strcmp(item->name, name)) {
        return;
    }

    fprintf(stderr, "iomfb: AP RPC '%s' answered; callback script passed "
            "barrier @%s\n", name, item->name);
    m->cb_next++;
    iomfb_callback_pump(m, ep);
}

/* Run script gates only once the AP RPC has actually completed. */
static void iomfb_after_rpc(DarwinIOMFB *m, uint8_t ep, const char name[5])
{
    if (m->hotplug_enabled && !m->hotplug_armed && !strcmp(name, "A389")) {
        m->hotplug_armed = true;
        m->hotplug_ep = ep;
        m->hotplug_timer = timer_new_ms(QEMU_CLOCK_VIRTUAL,
                                        iomfb_hotplug_timer_cb, m);
        timer_mod(m->hotplug_timer,
                  qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) +
                  (int64_t)m->hotplug_delay_sec * 1000);
        fprintf(stderr, "iomfb: first A389 answered; D575 hot-plug-detect "
                "armed for +%u s\n", m->hotplug_delay_sec);
    }
    iomfb_callback_barrier(m, ep, name);
    if (m->cb_script && !m->cb_started && m->cb_after && *m->cb_after &&
        !strcmp(name, m->cb_after)) {
        m->cb_started = true;
        fprintf(stderr, "iomfb: '%s' answered; starting the %u-entry callback "
                "script\n", name, m->cb_script->len);
        iomfb_callback_pump(m, ep);
    }
}

/*
 * The AP's completion for a callback we sent. Class 2 / subkind 1, carrying
 * our tag and our ack bit (rpc_callee_gated passes the slot as ctx, so
 * link_send_message re-derives both from slot[0]/slot[4], 0xa0cf2b0), with
 * the status in bits[47:16] -- zero on success.
 */
static void iomfb_callback_done(DarwinIOMFB *m, uint8_t ep, uint64_t msg)
{
    const unsigned tag = 0;
    uint32_t status = (uint32_t)(msg >> 16);

    if (m->hotplug_active) {
        m->cb_busy = m->hotplug_active = false;
        fprintf(stderr, "iomfb: D575 hot-plug-detect completed, status "
                "0x%x\n", status);
        if (status) {
            m->hotplug_failed = true;
            fprintf(stderr, "iomfb: D575 hot-plug-detect rejected; "
                    "producer stopped\n");
            return;
        }
        uint64_t dva = m->heap_dva + IOMFB_CB_REQ_BASE
                     + (uint64_t)tag * IOMFB_WINDOW
                     + sizeof(IOMFBRpcHdr) + IOMFB_HOTPLUG_IN_LEN;
        g_autofree uint8_t *out = g_malloc0(IOMFB_HOTPLUG_OUT_LEN);
        if (!iomfb_dma(m, dva, out, IOMFB_HOTPLUG_OUT_LEN, false)) {
            fprintf(stderr, "iomfb:   D575 output at dva 0x%" PRIx64
                    " could not be read\n", dva);
        } else {
            g_autoptr(GString) hex = g_string_new(NULL);
            for (uint32_t i = 0; i < 32; i++) {
                g_string_append_printf(hex, "%02x", out[i]);
            }
            fprintf(stderr, "iomfb:   D575 out: %s...\n", hex->str);
        }
        iomfb_callback_pump(m, ep);
        return;
    }
    if (m->swap_active) {
        fprintf(stderr, "iomfb: swap id %u D594 completed, status 0x%x\n",
                m->swap_ids[m->swap_head], status);
        m->cb_busy = m->swap_active = false;
        if (status) {
            m->swap_failed = true;
            return;
        }
        m->swap_head = (m->swap_head + 1) % IOMFB_SWAP_QUEUE_SIZE;
        m->swap_count--;
        iomfb_callback_pump(m, ep);
        iomfb_hotplug_try_send(m);
        return;
    }
    const IOMFBCallback *cb =
        &g_array_index(m->cb_script, IOMFBCallback, m->cb_next - 1);
    uint32_t in_len = cb->in ? cb->in->len : 0;

    m->cb_busy = false;

    if (!cb->out_len) {
        fprintf(stderr, "iomfb:   callback '%s' completed, status 0x%x, no output\n",
                cb->name, status);
    } else {
        uint64_t dva = m->heap_dva + IOMFB_CB_REQ_BASE
                     + (uint64_t)tag * IOMFB_WINDOW
                     + sizeof(IOMFBRpcHdr) + in_len;
        g_autofree uint8_t *out = g_malloc0(cb->out_len);
        if (!iomfb_dma(m, dva, out, cb->out_len, false)) {
            fprintf(stderr, "iomfb:   callback '%s' completed, status 0x%x, but "
                    "its output at dva 0x%" PRIx64 " could not be read\n",
                    cb->name, status, dva);
        } else {
            g_autoptr(GString) hex = g_string_new(NULL);
            for (uint32_t i = 0; i < cb->out_len && i < 32; i++) {
                g_string_append_printf(hex, "%02x", out[i]);
            }
            fprintf(stderr, "iomfb:   callback '%s' completed, status 0x%x, "
                    "out: %s%s\n", cb->name, status, hex->str,
                    cb->out_len > 32 ? "..." : "");
        }
    }

    iomfb_callback_pump(m, ep);
    iomfb_hotplug_try_send(m);
}

/*
 * Parse DARWIN_DCP_IOMFB_CB. Comma or space separated NAME[:INHEX[:OUTLEN]]
 * callbacks and @NAME barriers, eg. "D120::4,D586:9b040000fc090000:4,@A385,"
 * "D575". OUTLEN is C-style (0x for hex). A name is exactly four characters;
 * a barrier is exactly '@' plus four characters and accepts no fields.
 * Nothing else about callback names is validated here, because the point of
 * the harness is to send something the AP may reject and read what it says.
 */
static void iomfb_parse_callbacks(DarwinIOMFB *m, const char *spec)
{
    g_auto(GStrv) items = g_strsplit_set(spec, ", ", -1);

    m->cb_script = g_array_new(FALSE, TRUE, sizeof(IOMFBCallback));
    for (char **it = items; it && *it; it++) {
        if (!**it) continue;
        if (**it == '@') {
            if (strlen(*it) != 5 || strchr(*it + 1, ':')) {
                fprintf(stderr, "iomfb: DARWIN_DCP_IOMFB_CB: malformed "
                        "barrier \"%s\" (want @NAME, NAME exactly 4 chars); "
                        "skipped\n", *it);
                continue;
            }
            IOMFBCallback barrier = { .barrier = true };
            memcpy(barrier.name, *it + 1, 4);
            g_array_append_val(m->cb_script, barrier);
            fprintf(stderr, "iomfb: PROBE callback barrier scripted: @%s\n",
                    barrier.name);
            continue;
        }
        g_auto(GStrv) f = g_strsplit(*it, ":", 3);
        if (!f[0] || strlen(f[0]) != 4) {
            fprintf(stderr, "iomfb: DARWIN_DCP_IOMFB_CB: \"%s\" is not a 4-char "
                    "name; skipped\n", *it);
            continue;
        }
        IOMFBCallback cb = { 0 };
        memcpy(cb.name, f[0], 4);
        /* The heap holds the u32 whose big-endian bytes spell the name --
         * that is how rpc_callee_gated unpacks it at 0xa0cf108-0xa0cf120. */
        cb.name_be = ((uint32_t)(uint8_t)f[0][0] << 24)
                   | ((uint32_t)(uint8_t)f[0][1] << 16)
                   | ((uint32_t)(uint8_t)f[0][2] << 8)
                   |  (uint32_t)(uint8_t)f[0][3];
        if (f[1] && *f[1]) {
            if (strlen(f[1]) & 1) {
                fprintf(stderr, "iomfb: DARWIN_DCP_IOMFB_CB: odd hex digit count "
                        "for %s; skipped\n", cb.name);
                continue;
            }
            cb.in = g_byte_array_new();
            for (const char *q = f[1]; *q; q += 2) {
                char pair[3] = { q[0], q[1], 0 };
                char *end = NULL;
                uint8_t b = (uint8_t)strtoul(pair, &end, 16);
                if (end != pair + 2) {
                    fprintf(stderr, "iomfb: DARWIN_DCP_IOMFB_CB: bad hex for %s\n",
                            cb.name);
                    break;
                }
                g_byte_array_append(cb.in, &b, 1);
            }
        }
        if (f[1] && f[2] && *f[2]) {
            cb.out_len = (uint32_t)strtoul(f[2], NULL, 0);
        }
        g_array_append_val(m->cb_script, cb);
        fprintf(stderr, "iomfb: PROBE callback scripted: '%s' in %u out %u\n",
                cb.name, cb.in ? cb.in->len : 0, cb.out_len);
    }
}

/* --------------------------------------------------------------- class 0 -- */

/*
 * The AP announcing its shared heap. Reply with the class-1 init ack; see
 * step 2 in the header comment for why the hash goes in bits[47:16].
 */
static void iomfb_class0(DarwinIOMFB *m, uint8_t ep, uint64_t msg) {
    unsigned subkind = IOMFB_SUBKIND(msg);

    if (subkind != 1) {
        /*
         * Class 0 / subkind 0 exists (link_handle_message 0xa0cfb1c-0xa0cfb58
         * handles it, comparing (msg>>16) against the raw word at
         * 0xfffffff00b880c70 rather than its crc32, and resending the heap
         * announce). The AP has never sent us one, so there is nothing to
         * model from observation. Logged no-op, deliberately.
         */
        fprintf(stderr, "iomfb: ep 0x%02x class 0 subkind %u -- not modelled "
                "(no such message observed from this AP), ignored\n", ep, subkind);
        return;
    }

    m->heap_dva = msg >> 16;
    m->heap_known = true;
    fprintf(stderr, "iomfb: ep 0x%02x AP heap announce: dva 0x%" PRIx64 "\n",
            ep, m->heap_dva);

    if (m->level < 2) return;

    /*
     * class 1, subkind 0, tag 0, ack 0, hash in [47:16], phase left 0 (the AP
     * clamps it to at least 4 itself at 0xa0cfbf8).
     */
    uint64_t ack = ((uint64_t)IOMFB_FW_HASH << 16) | 0x0001ULL;
    iomfb_send(m, ep, ack, "class-1 init ack, firmware hash");

    /*
     * DARWIN_DCP_IOMFB_CB_AFTER='' (or 'ack') starts the callback script here,
     * as soon as the link is up. The default waits for a named inbound RPC
     * instead -- see iomfb_class2 -- because the AP has work of its own to
     * finish first and a callback that lands mid-start() tells us less.
     */
    if (m->cb_script && (!m->cb_after || !*m->cb_after ||
                         !strcmp(m->cb_after, "ack"))) {
        m->cb_started = true;
        iomfb_callback_pump(m, ep);
    }
}

/* --------------------------------------------------------------- class 2 -- */

/*
 * An RPC request sits in the AP's shared heap. Read it, log it, and (level 3)
 * complete it.
 *
 * Everything about the reply's shape is sourced in step 4 of the header
 * comment. What we cannot source is any *method*: the FourCC namespace of
 * this firmware has not been derived, so we answer status 0 with a zeroed
 * output buffer and say so in the log. That is a stub, not a model.
 */
static void iomfb_class2(DarwinIOMFB *m, uint8_t ep, uint64_t msg) {
    unsigned subkind = IOMFB_SUBKIND(msg);
    uint32_t off = IOMFB_RPC_OFF(msg), size = IOMFB_RPC_SIZE(msg);

    if (subkind == 1) {
        unsigned tag = IOMFB_TAG(msg);
        if (IOMFB_ACK(msg) == 0 && tag < IOMFB_TAGS && m->swap_nested[tag]) {
            uint32_t status = (uint32_t)(msg >> 16);
            m->swap_nested[tag] = false;
            fprintf(stderr, "iomfb: swap id %u D594 nested completed, status "
                    "0x%x; releasing A408 tag %u\n",
                    m->swap_nested_ids[tag], status, tag);
            iomfb_dcp_event(m, 'C', "A408", ep, 0, 0, "nested-D594");
            iomfb_send(m, ep, 0x42ULL | ((uint64_t)tag << 10) |
                       ((uint64_t)status << 16), "A408 after nested D594");
            iomfb_after_rpc(m, ep, "A408");
            return;
        }
        /*
         * A completion for a callback we sent. rpc_callee_gated builds it as
         * (our header & 0xff3e) | 0x40 with our tag and ack bit, so the only
         * thing that identifies it is that we have one outstanding.
         */
        if (m->cb_busy && IOMFB_ACK(msg) == 1 && IOMFB_TAG(msg) == 0) {
            fprintf(stderr, "iomfb: ep 0x%02x class 2 subkind 1 (callback "
                    "completion) tag %u ack %u status 0x%x\n",
                    ep, IOMFB_TAG(msg), IOMFB_ACK(msg), (uint32_t)(msg >> 16));
            iomfb_callback_done(m, ep, msg);
        } else {
            fprintf(stderr, "iomfb: ep 0x%02x unexpected class 2 subkind 1 "
                    "(callback busy %u, tag %u, ack %u) -- ignored\n",
                    ep, m->cb_busy, IOMFB_TAG(msg), IOMFB_ACK(msg));
        }
        return;
    }
    if (subkind != 0) {
        fprintf(stderr, "iomfb: ep 0x%02x class 2 subkind %u from the AP -- not modelled, "
                "ignored\n", ep, subkind);
        return;
    }

    /*
     * A normal AP call uses ack 0.  While the AP is handling our D-series
     * callback, calls nested through rpc_caller_gated use the callback slot
     * array and consequently carry ack 1.  D120 demonstrates this directly:
     * its first nested request is A389 (wrapper 0xfffffff00917f11c), followed
     * by nine more ack-1 calls before the callback completion.  The old model
     * called these messages reflections and dumped IOMFB_CB_REQ_BASE, which
     * could only read back the D120 request we wrote; it never inspected the
     * AP request window and therefore supplied no evidence of a reflection.
     *
     * Accept callback-context traffic only while our one tag-0 callback is
     * outstanding.  This bounded gate preserves the normal ack-0 path and
     * fails closed on an unsolicited or differently tagged ack-1 request.
     */
    bool nested = IOMFB_ACK(msg) != 0;
    unsigned tag = IOMFB_TAG(msg);
    if (nested && (!m->cb_busy || tag != 0)) {
        fprintf(stderr, "iomfb: ep 0x%02x unexpected ack-1 class-2 request "
                "outside callback context (busy %u, tag %u) -- ignored\n",
                ep, m->cb_busy, tag);
        return;
    }

    if (!m->heap_known) {
        fprintf(stderr, "iomfb: ep 0x%02x RPC at offset 0x%x size 0x%x, but the AP never "
                "announced a heap; cannot read it\n", ep, off, size);
        return;
    }
    if (tag >= IOMFB_TAGS) {
        fprintf(stderr, "iomfb: ep 0x%02x RPC tag %u exceeds the %u-slot "
                "channel -- ignored\n", ep, tag, IOMFB_TAGS);
        return;
    }
    if (size < sizeof(IOMFBRpcHdr) || off > IOMFB_WINDOW ||
        size > IOMFB_WINDOW - off) {
        fprintf(stderr, "iomfb: ep 0x%02x RPC size 0x%x is smaller than the 0xc-byte "
                "header or outside its 0x%x-byte window at offset 0x%x; ignored\n",
                ep, size, IOMFB_WINDOW, off);
        return;
    }

    /*
     * The offset is relative to *this tag's* 32 KB TX window, not to the
     * heap: rpc_caller_gated reads and writes at slot[8] + offset
     * (0xa0ce608). link_state_init assigns heap+0x00000 to the ack-0 array
     * (0xa0cf664) and heap+0x20000 to the ack-1/callback array (0xa0cf6a0),
     * each plus tag*0x8000. Our outbound D-series request lives in the
     * separate ack-1 RX window at heap+0x40000 (0xa0cf6cc), which is why
     * reading that old location returned D120 instead of nested A389.
     */
    uint32_t window_base = nested ? IOMFB_CB_TX_BASE : IOMFB_AP_REQ_BASE;
    uint64_t win = m->heap_dva + window_base
                 + (uint64_t)tag * IOMFB_WINDOW;
    g_autofree uint8_t *buf = g_malloc0(size);
    if (!iomfb_dma(m, win + off, buf, size, false)) {
        fprintf(stderr, "iomfb: ep 0x%02x could not read the RPC at dva 0x%" PRIx64
                "+0x%x\n", ep, win, off);
        return;
    }

    IOMFBRpcHdr h;
    memcpy(&h, buf, sizeof(h));
    /* The AP prints this FourCC big-endian (0xa0ce4a8-0xa0ce4c4); match it. */
    char name[5] = {
        (char)(h.name >> 24), (char)(h.name >> 16), (char)(h.name >> 8), (char)h.name, 0
    };
    for (int i = 0; i < 4; i++) {
        if (name[i] < 0x20 || name[i] > 0x7e) name[i] = '.';
    }

    m->rpcs++;
    fprintf(stderr, "iomfb: ep 0x%02x %sRPC #%" PRIu64
            " '%s' (0x%08x) in %u out %u "
            "at heap+0x%x size 0x%x tag %u ack %u flag9 %u\n",
            ep, nested ? "nested callback-context AP " : "", m->rpcs,
            name, h.name, h.in_len, h.out_len, off, size,
            IOMFB_TAG(msg), IOMFB_ACK(msg), IOMFB_FLAG9(msg));
    iomfb_dcp_event(m, 'R', name, ep, h.in_len, h.out_len,
                    nested ? "nested" : "");

    if (m->rpc_trace) {
        /*
         * Do not read past the message if a malformed header overstates its
         * input. Keep the claimed lengths in the context line so malformed
         * traffic remains diagnosable, and mark how many input bytes were
         * actually available to the tracer.
         */
        uint32_t input_available = size - sizeof(h);
        uint32_t input_len = MIN(h.in_len, input_available);
        unsigned slot = tag;
        uint32_t window_off = window_base + slot * IOMFB_WINDOW;
        uint64_t request_dva = win + off;
        uint64_t input_dva = request_dva + sizeof(h);
        uint64_t output_dva = input_dva + h.in_len;
        uint64_t occurrence = iomfb_trace_occurrence(m, &h,
                                                     buf + sizeof(h),
                                                     input_len);

        fprintf(stderr, "iomfb: TRACE AP->DCP rpc #%" PRIu64
                " method '%s' fourcc 0x%08x slot %u tag %u ack %u flag9 %u "
                "in %u (available %u) out %u total 0x%x occurrence #%" PRIu64
                " body %s\n",
                m->rpcs, name, h.name, slot, tag, IOMFB_ACK(msg),
                IOMFB_FLAG9(msg), h.in_len, input_len, h.out_len, size,
                occurrence, occurrence == 1 ? "follows" : "same-as-first");
        fprintf(stderr, "iomfb: TRACE   heap-dva 0x%" PRIx64
                " window heap+0x%x request-off 0x%x request-dva 0x%" PRIx64
                " input-dva 0x%" PRIx64 " output-dva 0x%" PRIx64 "\n",
                m->heap_dva, window_off, off, request_dva, input_dva,
                output_dva);
        if (occurrence == 1) {
            iomfb_trace_sparse_input(buf + sizeof(h), input_len);
        }
    }

    /* The AP's own accounting: total = 0xc + in_len + out_len (0xa0ce4d8). */
    if ((uint64_t)sizeof(h) + h.in_len + h.out_len != size) {
        fprintf(stderr, "iomfb:   malformed RPC: 0xc + in + out = 0x%" PRIx64
                " but the message says 0x%x; ignored\n",
                (uint64_t)sizeof(h) + h.in_len + h.out_len, size);
        return;
    }

    if (m->debug) {
        uint32_t in_len = h.in_len;
        if (in_len > size - sizeof(h)) in_len = size - sizeof(h);
        iomfb_hexdump("in", buf + sizeof(h), in_len);
    }

    if (m->level < 3) {
        fprintf(stderr, "iomfb:   not answering (DARWIN_DCP_IOMFB=%u; 3 answers RPCs)\n",
                m->level);
        return;
    }

    /*
     * Fill the output region. The default is all zeroes: deterministic, and
     * the only answer that does not invent behaviour for a method we have
     * not derived. DARWIN_DCP_IOMFB_OUT can substitute canned bytes for one
     * FourCC so a probe can test a hypothesis -- see the out_override
     * comment on DarwinIOMFB. Both paths are logged by name.
     *
     * Note the AP poisons its own out buffer with 0xaa before the call (eg.
     * the A401 stub's `movi v0.16b, 0xaa; stur s0, [x29,-4]` at
     * 0xa0c8a90-0xa0c8a94), so leaving the region untouched would hand the
     * driver 0xaaaaaaaa rather than nothing.
     */
    const char *how = "zeroed";
    if (h.out_len && (uint64_t)sizeof(h) + h.in_len + h.out_len <= size) {
        g_autofree uint8_t *out = g_malloc0(h.out_len);
        GByteArray *ov = m->out_override ?
            g_hash_table_lookup(m->out_override, name) : NULL;
        if (ov) {
            memcpy(out, ov->data, MIN(ov->len, h.out_len));
            how = "PROBE override";
        } else if (h.name == 0x41343839) {
            /*
             * Built-in A489 answer. The kernel issues A489 and keeps
             * bit 0 of the first response byte as the display provider's
             * [0x389] (0xfffffff00a188a90: ldurb; and w0, w8, #1; strb).
             * The hot-plug latch [0x38a] is stored only when [0x389] is 1
             * (hotPlug_notify_gated, 0xfffffff00a178c94-0xa178cb8), and the
             * mode query returns [0x38a] & 1 (selector 0x19,
             * 0xfffffff00a176eb4). Bit 0 set is therefore required for the
             * panel to activate; only bit 0 is consumed, the rest stays 0.
             * A PROBE override still wins when present.
             */
            out[0] = 0x01;
            how = "built-in A489";
        }
        uint64_t out_dva = win + off + sizeof(h) + h.in_len;
        if (!iomfb_dma(m, out_dva, out, h.out_len, true)) {
            fprintf(stderr, "iomfb:   could not write the %u-byte output region at dva "
                    "0x%" PRIx64 "\n", h.out_len, out_dva);
        } else if (m->debug) {
            iomfb_hexdump("out", out, h.out_len);
        }
    }

    /* Copy before any completion can release the native surface mapping. */
    if (m->scanout_enabled && h.name == 0x41343038) {
        iomfb_scanout(buf + sizeof(h), h.in_len);
    }
    if (m->swap_enabled && h.name == 0x41343038 && !nested) {
        uint32_t id;
        if (darwin_iomfb_swap_id(buf + sizeof(h), h.in_len, h.out_len, &id)) {
            if (!iomfb_swap_send_nested(m, ep, tag, id)) {
                fprintf(stderr, "iomfb: A408 tag %u retained after D594 send failure\n", tag);
            }
            return;
        }
    }

    /*
     * class 2, subkind 1 (0x42 in the header, which is exactly what the
     * waiter masks for at 0xa0ce750-75c), the request's own tag and ack bit
     * so link_handle_message's (ack<<32)|tag lookup finds the caller, and
     * status 0 in bits[47:16].
     */
    uint64_t reply = 0x42ULL
                   | ((uint64_t)IOMFB_ACK(msg) << 8)
                   | ((uint64_t)IOMFB_TAG(msg) << 10);
    char what[96];
    snprintf(what, sizeof(what), "class-2 completion for '%s', status 0, out %s", name, how);
    iomfb_dcp_event(m, 'C', name, ep, h.in_len, h.out_len, how);
    iomfb_send(m, ep, reply, what);

    /* Legacy callback-context A408 handling; normal ack-0 submissions use
     * the caller's own slot above. Also retain the async queue for old
     * checkpoints with a D594 already in flight. */
    if (m->swap_enabled && h.name == 0x41343038) {
        iomfb_swap_enqueue(m, buf + sizeof(h), h.in_len, h.out_len);
        if (!m->cb_script || m->cb_next == m->cb_script->len) {
            iomfb_swap_pump(m, ep);
        }
    }

    iomfb_after_rpc(m, ep, name);
}

/* ------------------------------------------------------------- dispatch -- */

bool darwin_iomfb_handle(DarwinIOMFB *m, uint8_t ep, uint64_t msg) {
    unsigned cls = IOMFB_CLASS(msg);

    fprintf(stderr, "iomfb: AP -> IOP ep 0x%02x 0x%016" PRIx64
            " | class %u subkind %u ack %u flag9 %u tag %u payload 0x%" PRIx64 "\n",
            ep, msg, cls, IOMFB_SUBKIND(msg), IOMFB_ACK(msg), IOMFB_FLAG9(msg),
            IOMFB_TAG(msg), msg >> 16);

    if (cls != 2) {
        iomfb_dcp_event(m, 'M', "-", ep, 0, 0, "");
    }

    if (m->level < 2) {
        return true;    /* decode-only mode: never answer */
    }

    switch (cls) {
    case 0:
        iomfb_class0(m, ep, msg);
        break;
    case 2:
        iomfb_class2(m, ep, msg);
        break;
    case 1:
        /*
         * The AP's own class-1 message, sent by fcn.fffffff00a0ce0f0 when
         * chan+0x260 == 1 (0xa0ce108-0xa0ce118, always 0x0004000000000001).
         * It is the mirror of the ack we send in step 2 and needs no reply
         * that we can source. Logged no-op.
         */
        fprintf(stderr, "iomfb: ep 0x%02x class 1 from the AP (its own init ack); "
                "no reply modelled\n", ep);
        break;
    default:
        /*
         * Class 3 is only inferred to exist from the 2-bit width of the field
         * and an unreached error branch at 0xa0d0310. Never observed.
         */
        fprintf(stderr, "iomfb: ep 0x%02x class %u -- never observed, not modelled, "
                "ignored\n", ep, cls);
        break;
    }
    return true;
}

DarwinIOMFB *darwin_iomfb_new(DeviceState *asc, DeviceState *dart, unsigned sid,
                              unsigned level) {
    DarwinIOMFB *m = g_new0(DarwinIOMFB, 1);
    const char *dbg = getenv("DARWIN_DCP_IOMFB_DEBUG");
    const char *trace = getenv("DARWIN_DCP_IOMFB_RPC_TRACE");

    m->asc = asc;
    m->dart = dart;
    m->sid = sid;
    m->level = level;
    const char *scanout = getenv("DARWIN_DCP_IOMFB_SCANOUT");
    m->scanout_enabled = level >= 3 && scanout && !strcmp(scanout, "1");
    const char *complete = getenv("DARWIN_DCP_IOMFB_COMPLETE");
    m->swap_enabled = level >= 3 && complete && !strcmp(complete, "1");
    if (m->swap_enabled) {
        fprintf(stderr, "iomfb: native A408/D594 swap completion enabled\n");
    }
    const char *hotplug = getenv("DARWIN_DCP_IOMFB_HOTPLUG");
    m->hotplug_enabled = level >= 3 && hotplug && !strcmp(hotplug, "1");
    m->hotplug_delay_sec = 30;
    const char *hpdelay = getenv("DARWIN_DCP_IOMFB_HOTPLUG_DELAY");
    if (hpdelay && *hpdelay) {
        char *end = NULL;
        unsigned long v = strtoul(hpdelay, &end, 0);
        if (end != hpdelay && !*end && v <= 3600) {
            m->hotplug_delay_sec = (unsigned)v;
        } else {
            fprintf(stderr, "iomfb: DARWIN_DCP_IOMFB_HOTPLUG_DELAY '%s' "
                    "is not a number of seconds (0-3600); using %u\n",
                    hpdelay, m->hotplug_delay_sec);
        }
    }
    if (m->hotplug_enabled) {
        fprintf(stderr, "iomfb: native one-shot D575 hot-plug-detect "
                "producer enabled (%u s after the first A389)\n",
                m->hotplug_delay_sec);
    }
    m->debug = dbg && dbg[0] && dbg[0] != '0';
    m->rpc_trace = trace && trace[0] && trace[0] != '0';
    if (m->rpc_trace) {
        m->rpc_trace_seen = g_hash_table_new_full(g_bytes_hash, g_bytes_equal,
                                                  (GDestroyNotify)g_bytes_unref,
                                                  g_free);
        fprintf(stderr, "iomfb: TRACE AP->DCP RPC tracing enabled by "
                "DARWIN_DCP_IOMFB_RPC_TRACE\n");
    }

    const char *dcp_trace = getenv("DARWIN_DCP_TRACE");
    if (dcp_trace && *dcp_trace) {
        iomfb_dcp_event_open(m, dcp_trace);
    }

    if (level >= 4) {
        for (size_t i = 0; i < ARRAY_SIZE(iomfb_level4); i++) {
            g_autofree char *one = g_strdup_printf("%s=%s", iomfb_level4[i].name,
                                                   iomfb_level4[i].hex);
            iomfb_parse_overrides(m, one);
        }
    }

    /* The environment wins over the table, so a probe can contradict it. */
    const char *ov = getenv("DARWIN_DCP_IOMFB_OUT");
    if (ov && *ov) {
        iomfb_parse_overrides(m, ov);
    }

    /*
     * The outbound callback script. Unset means nothing is ever sent in that
     * direction, which is the default at every level: the transport is
     * modelled, the policy is not. A353 is the default trigger because it is
     * the last RPC the AP issues before going quiet (docs/re/iomfb-link.md,
     * addendum 2, run M4/L4).
     */
    const char *cbs = getenv("DARWIN_DCP_IOMFB_CB");
    if (cbs && *cbs) {
        const char *after = getenv("DARWIN_DCP_IOMFB_CB_AFTER");
        const char *f9 = getenv("DARWIN_DCP_IOMFB_CB_FLAG9");
        m->cb_after = g_strdup(after ? after : "A353");
        m->cb_flag9 = !(f9 && f9[0] == '0');
        iomfb_parse_callbacks(m, cbs);
        fprintf(stderr, "iomfb: PROBE callback script has %u entr%s, starting "
                "after %s\n", m->cb_script->len,
                m->cb_script->len == 1 ? "y" : "ies",
                *m->cb_after ? m->cb_after : "the class-1 init ack");
    }

    fprintf(stderr, "darwin-iomfb: link on ep 0x37, level %u (%s), dart %s sid %u\n",
            level,
            level >= 4 ? "handshake + RPC completions + measured answers" :
            level >= 3 ? "handshake + RPC completions" :
            level >= 2 ? "handshake, RPCs decoded but unanswered" :
                         "decode only",
            dart ? "ok" : "MISSING", sid);
    return m;
}
