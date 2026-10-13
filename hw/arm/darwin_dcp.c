/*
 * darwin-dcp: Display Coprocessor personality on top of darwin-asc
 *
 * On A14+/M1+ the display is driven entirely by the DCP firmware; the AP's
 * AppleDCP / IOMobileFramebuffer / AppleCLCD2 stack talks to it over RTKit
 * endpoints. This file is the DCP-shaped glue: it decides which endpoints
 * exist and which protocol runs on each, and owns nothing else.
 *
 * Endpoint map (docs/re/dcp-bringup.md, from the iOS 27 kernelcache's
 * IOKitPersonalities; confirmed live by the RTKit endpoint-start trace):
 *
 *   0x20 .. 0x2a   DCPEndpoint1..11   AppleDCPEndpointV2 -- AFK ring
 *                                     transport with EPIC framing on top.
 *                                     Handled here by darwin_afk.c.
 *   0x37           DCPEndpoint24      AppleDCPLinkServiceSoC -- IOMFB, a
 *                                     different RPC framing that rides
 *                                     directly on RTKit, *not* AFK. Not
 *                                     advertised yet, so XNU never starts it.
 *
 * What works today: the RTKit handshake (darwin_asc.c), the AFK transport
 * handshake for every 0x20..0x2a endpoint (darwin_afk.c), and one EPIC
 * REPORT/PUBLISH per endpoint announcing a service by name (darwin_epic.c),
 * which is what XNU's sub-driver personalities match on -- every one of them
 * is `IOProviderClass = AFKEndpointInterface` plus
 * `IOPropertyMatch = { EPICName: ... }` in the kernelcache's
 * __PRELINK_INFO. What does not: any command/response traffic *after* a
 * driver binds. Commands the AP sends us are decoded and logged, and
 * deliberately not answered -- see dcp_afk_recv().
 *
 * WHAT TO ANNOUNCE is policy, and it lives here rather than in darwin_epic.c.
 * The service list below is the "confirmed both sides" table from
 * docs/re/dcp-firmware-services.md: each name appears both as an `-epic`
 * string in the real t8140 DCP firmware and as an `EPICName` IOPropertyMatch
 * in this kernelcache, so XNU really will try to bind the named class.
 *
 * Which endpoint carries which service is *not* known for t8140 -- the
 * endpoint-to-service correlation in docs/re/afk-epic-references.md sec. 4 is
 * M1-era and explicitly unconfirmed. It should not matter: matching keys on
 * the announced properties, not on the endpoint number. The default is
 * therefore one service on one endpoint, overridable without a rebuild:
 *
 *   DARWIN_DCP_EPIC=off                   announce nothing (pre-EPIC behaviour)
 *   DARWIN_DCP_EPIC=all                   announce every service in dcp_services[]
 *   DARWIN_DCP_EPIC=dcpav-device-epic     announce just that one
 *   DARWIN_DCP_EPIC_EP=0x22               ...on this endpoint (default 0x20)
 *   DARWIN_DCP_EPIC_OPTIONS=0             packet header options byte
 *
 * Tracing: DARWIN_ASC_DEBUG=1 for the mailbox, DARWIN_AFK_DEBUG=1 for the
 * ring transport, DARWIN_DART_DEBUG=1 for the IOMMU underneath it. The
 * announce itself always logs one line per service (prefix "dcp:", which is
 * what tools/probe.sh filters device-model traces on).
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "migration/vmstate.h"
#include "xnu/darwin_asc.h"
#include "xnu/darwin_afk.h"
#include "xnu/darwin_afk_state.h"
#include "xnu/darwin_dart.h"
#include "xnu/darwin_dcp.h"
#include "xnu/darwin_epic.h"
#include "xnu/darwin_iomfb.h"

/*
 * One announceable EPIC service. `epic_name` is the match key; `provider` is
 * the IOClass the kernelcache pairs it with -- we publish it as
 * `EPICProviderClass` because the real firmware's string table keeps
 * EPICName/EPICProviderClass/EPICUnit adjacent (dcpfw+0x3f6ef6..0x3f6f15) even
 * though this kernelcache never matches on it.
 */
typedef struct {
    const char *epic_name;
    const char *provider;
} DCPService;

/* docs/re/dcp-firmware-services.md, "Confirmed both sides" table. */
static const DCPService dcp_services[] = {
    { "dcpav-controller-epic",       "DCPAVControllerProxy" },
    { "dcpav-device-epic",           "DCPAVDeviceProxy" },
    { "dcpav-service-epic",          "DCPAVServiceProxy" },
    { "dcpav-video-interface-epic",  "DCPAVVideoInterfaceProxy" },
    { "dcpav-power-epic",            "DCPAVPowerControllerProxy" },
    { "dcpav-audio-interface-epic",  "DCPAVAudioInterfaceProxy" },
    { "dcpav-cec-interface-epic",    "DCPAVCECInterfaceProxy" },
    { "dcpav-sac-epic",              "DCPAVRemoteSACControllerProxy" },
    { "dcpdp-controller-epic",       "DCPDPControllerProxy" },
    { "dcpdp-device-epic",           "DCPDPDeviceProxy" },
    { "dcpdp-service-epic",          "DCPDPServiceProxy" },
    { "dcpdptx-port-epic",           "AppleDCPDPTXRemotePortProxy" },
    { "dcp-lpdptx-port-epic",        "AppleDCPLPDPTXPortProxy" },
    { "dcpdptx-hdcp-interface",      "AppleDCPDPTXRemoteHDCPInterfaceProxy" },
    { "dcpdptx-hdcp-auth-session",   "AppleDCPDPTXRemoteHDCPAuthSessionProxy" },
    { "dcpmipi-controller-epic",     "DCPMIPIControllerProxy" },
};

typedef struct DarwinDCP {
    DeviceState *asc;
    DarwinAFK *afk;
    /*
     * The IOMFB "link" protocol on endpoint 0x37, or NULL when 0x37 is not
     * advertised. It is a different framing from AFK and lives in
     * darwin_iomfb.c; see the DARWIN_DCP_IOMFB note below dcp_eps_adv.
     */
    DarwinIOMFB *iomfb;
    unsigned iomfb_level;
    uint64_t msgs;

    /* announce policy, resolved once at create time */
    bool announce;          /* DARWIN_DCP_EPIC != "off" */
    bool announce_all;      /* DARWIN_DCP_EPIC == "all" */
    bool announce_dcpexpert; /* announce the DCP expert's interface too */
    const char *only;       /* a single EPICName, or NULL */
    uint8_t announce_ep;    /* which endpoint to announce on */
    uint8_t options;        /* EPIC packet header options byte */
    uint16_t next_iface;    /* firmware-chosen interface ids, 1-based */
} DarwinDCP;

static const VMStateDescription vmstate_darwin_dcp = {
    .name = "darwin-dcp",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]) {
        VMSTATE_UINT64(msgs, DarwinDCP),
        VMSTATE_UINT16(next_iface, DarwinDCP),
        VMSTATE_END_OF_LIST()
    },
};

/*
 * Endpoints the firmware advertises in the RTKit endpoint map. 0x20..0x2a is
 * what the iOS 27 kernelcache calls DCPEndpoint1..11; XNU issues a START_EP
 * for every one of them and then an AFK INIT on each, which is exactly what
 * the trace shows. 0x37 (IOMFB) is deliberately absent: nothing models that
 * protocol yet, and advertising an endpoint we cannot answer only moves the
 * stall somewhere harder to read.
 */
static const uint8_t dcp_eps[] = {
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a
};

/*
 * The advertised set, built at create time. dcp_eps above is the AFK block;
 * a non-zero DARWIN_DCP_IOMFB appends 0x37.
 *
 * 0x37 is DCPEndpoint24 / AppleDCPLinkServiceSoC -- IOMFB, the endpoint the
 * *framebuffer* actually rides on. It speaks a different framing directly on
 * RTKit, not AFK; darwin_iomfb.c models it. Off by default so the known-good
 * `-enable dcp` boot (shell reached, 0 panics, 11/11 AFK endpoints) cannot
 * regress on it.
 *
 * The value is a level, passed straight to darwin_iomfb_new():
 *
 *   DARWIN_DCP_IOMFB=1   advertise 0x37, decode and log, answer nothing.
 *                        Merely advertising it is what starts the whole
 *                        framebuffer stack: AppleDCPLinkService matches,
 *                        "IOMFB: AP DRIVER START!", IOMobileFramebufferAP
 *                        ::start on disp0.
 *   DARWIN_DCP_IOMFB=2   + the class-0/class-1 link handshake, and decode the
 *                        class-2 RPC requests that follow without answering.
 *   DARWIN_DCP_IOMFB=3   + answer those RPCs (status 0, zeroed output).
 *   DARWIN_DCP_IOMFB=4   + the canned per-method answers a measurement has
 *                        justified. This is the level at which AppleCLCD2
 *                        binds, starts *and* registers on the disp0 nub.
 *   DARWIN_DCP_IOMFB_DEBUG=1        hexdump every RPC body.
 *   DARWIN_DCP_IOMFB_OUT='A401=01'  override one method's output bytes.
 */
static uint8_t dcp_eps_adv[ARRAY_SIZE(dcp_eps) + 1];
static unsigned dcp_eps_adv_n;

static void dcp_started(void *opaque) {
    DarwinDCP *d = opaque;
    fprintf(stderr, "dcp: coprocessor booted\n");
    // darwin_asc_create() runs before the IOMFB link model, so tolerate
    // a callback arriving during ASC realize.
    if (d->iomfb) darwin_iomfb_link_up(d->iomfb);
}

static void dcp_ep_start(void *opaque, uint8_t ep, uint32_t flag) {
    DarwinDCP *d = opaque;
    // darwin_asc_create() runs before darwin_afk_new(), so tolerate a
    // callback arriving during ASC realize.
    if (d->afk) darwin_afk_ep_start(d->afk, ep, flag);
}

static bool dcp_handle(void *opaque, uint8_t ep, uint64_t msg) {
    DarwinDCP *d = opaque;
    d->msgs++;
    if (d->afk && darwin_afk_owns_endpoint(d->afk, ep)) {
        return darwin_afk_handle(d->afk, ep, msg);
    }
    if (ep == 0x37 && d->iomfb) {
        /*
         * Endpoint 0x37 (AppleDCPLinkServiceSoC). Not AFK, not EPIC: the
         * mailbox word itself is the message. Everything about that framing,
         * and every kernelcache address it came from, is in darwin_iomfb.c.
         */
        return darwin_iomfb_handle(d->iomfb, ep, msg);
    }

    // Endpoints we advertise but do not speak (and the RTKit system
    // endpoints darwin_asc.c does not consume). Log, never fault.
    fprintf(stderr, "dcp: AP -> ep 0x%02x msg 0x%016" PRIx64 " (type 0x%02x, no protocol modelled)\n",
            ep, msg, (unsigned)(msg >> 48));
    return true;
}

/*
 * Announce one service on `ep` as an EPIC REPORT/PUBLISH.
 *
 * The property dictionary is what XNU turns into the nub's property table
 * (0xfffffff008b7bd5c onwards), so it has to carry everything anyone matches
 * on or reads:
 *
 *   EPICName           the IOPropertyMatch key of every DCP sub-driver
 *                      personality in this kernelcache
 *   EPICProviderClass  the class the firmware pairs with that name
 *   EPICUnit           instance index; 0 for the single-instance services
 *   name               read back explicitly at 0xfffffff008b7bdf0
 *   interface-name     read back at 0xfffffff008b7be3c and used to setName()
 *                      the nub, so it is also what an IONameMatch personality
 *                      would see
 *
 * The AP adds "interface-id" itself from the message header, so we must not.
 */
static bool dcp_announce(DarwinDCP *d, uint8_t ep, const DCPService *svc) {
    const DarwinEpicProp props[] = {
        { .key = "EPICName",          .str = svc->epic_name },
        { .key = "EPICProviderClass", .str = svc->provider },
        { .key = "EPICUnit",          .num = 0, .bits = 64 },
        /*
         * Required, and its absence is what kept every DCPAV*Proxy from
         * starting. They all share DCPAVProxy::start (0xfffffff009b03e40),
         * which checks, in order: OSDynamicCast(AFKEndpointInterface,
         * provider), getWorkLoop(), IOService::start, then
         *
         *   provider->getProperty("EPICLocation") must be an OSString
         *   (0xfffffff009b04088-0xfffffff009b040ac)
         *
         * before EPICUnit. Without it the proxy fails out with
         * "DCPAVRemoteSACControllerProxy failed to start".
         *
         * The value is compared against "External"; IOAVFamily
         * (0xfffffff009db7868) maps it to an "External"/"Embedded" Location
         * property, and the DCP firmware's own string table carries exactly
         * those two next to the EPIC* keys (dcpfw+0x3f65d5, +0x3f65de).
         * "Embedded" is the built-in panel, which is what we are.
         */
        { .key = "EPICLocation",      .str = "Embedded" },
        { .key = "name",              .str = svc->epic_name },
        { .key = "interface-name",    .str = svc->epic_name },
    };
    size_t plen = 0;
    g_autofree uint8_t *blob = darwin_epic_serialize_props(props, ARRAY_SIZE(props), &plen);

    uint16_t iface = d->next_iface++;
    size_t flen = 0;
    g_autofree uint8_t *frame =
        darwin_epic_build_publish(iface, svc->epic_name, blob, plen, d->options, &flen);

    /*
     * afk_qe.channel and afk_qe.type are 0: iOS 27's AP writes 0 in both and
     * its ring drain never reads either back (it reads only magic and size,
     * 0xfffffff008b94a7c / 0xfffffff008b9492c). The EPIC message header inside
     * the payload is what carries the multiplexing.
     */
    bool ok = darwin_afk_send_qe(d->afk, ep, 0, 0, frame, (uint32_t)flen, false);
    fprintf(stderr, "dcp: ep 0x%02x announce EPICName=%s provider=%s iface-id %u "
            "frame 0x%zx bytes (props 0x%zx) -> %s\n",
            ep, svc->epic_name, svc->provider, iface, flen, plen,
            ok ? "queued" : "FAILED (ring full, or DMA unreachable)");

    // The exact bytes matter and are awkward to reconstruct from a panic, so
    // dump them when the transport is already being traced.
    if (getenv("DARWIN_AFK_DEBUG")) {
        g_autoptr(GString) s = g_string_new(NULL);
        for (size_t i = 0; i < flen; i++) {
            g_string_append_printf(s, "%s%02x", (i && !(i & 15)) ? "\n dcp:   " : " ", frame[i]);
        }
        fprintf(stderr, "dcp:   %s\n", s->str);
    }
    return ok;
}

/*
 * The DCP expert's endpoint interface.
 *
 * No EPICName personality matches this service -- the kernelcache has
 * none for it. AppleDCPExpert finds it by name instead: when the device
 * tree reports a remote power state, its start() registers a
 * service-interest notification for a service named "dcpexpert-service"
 * whose "role" property equals the role from its own device-tree node
 * ("DCP"), and waits for the AFK layer to hand it the interface
 * (kc 0xfffffff008a2bbdc). This publish is what creates that service:
 * the frame name and the "name"/"interface-name" properties are what
 * the nub is named from, and "role" rides along as a plain registry
 * property, which is all the expert's property match looks at.
 * "dcpexpert-epic" is the name the firmware keeps for the service
 * (dcpfw+0x3e8180); nothing on the AP matches on it.
 */
static bool dcp_announce_dcpexpert(DarwinDCP *d, uint8_t ep) {
    const DarwinEpicProp props[] = {
        { .key = "EPICName",       .str = "dcpexpert-epic" },
        { .key = "EPICUnit",       .num = 0, .bits = 64 },
        { .key = "name",           .str = "dcpexpert-service" },
        { .key = "interface-name", .str = "dcpexpert-service" },
        { .key = "role",           .str = "DCP" },
    };
    size_t plen = 0;
    g_autofree uint8_t *blob = darwin_epic_serialize_props(props, ARRAY_SIZE(props), &plen);

    uint16_t iface = d->next_iface++;
    size_t flen = 0;
    g_autofree uint8_t *frame =
        darwin_epic_build_publish(iface, "dcpexpert-service", blob, plen, d->options, &flen);

    bool ok = darwin_afk_send_qe(d->afk, ep, 0, 0, frame, (uint32_t)flen, false);
    fprintf(stderr, "dcp: ep 0x%02x announce name=dcpexpert-service EPICName=dcpexpert-epic "
            "iface-id %u frame 0x%zx bytes (props 0x%zx) -> %s\n",
            ep, iface, flen, plen, ok ? "queued" : "FAILED (ring full, or DMA unreachable)");

    if (getenv("DARWIN_AFK_DEBUG")) {
        g_autoptr(GString) s = g_string_new(NULL);
        for (size_t i = 0; i < flen; i++) {
            g_string_append_printf(s, "%s%02x", (i && !(i & 15)) ? "\n dcp:   " : " ", frame[i]);
        }
        fprintf(stderr, "dcp:   %s\n", s->str);
    }
    return ok;
}

static void dcp_afk_started(void *opaque, uint8_t ep) {
    DarwinDCP *d = opaque;

    if (!d->announce) {
        fprintf(stderr, "dcp: AFK endpoint 0x%02x is up; announcing nothing "
                "(DARWIN_DCP_EPIC=off)\n", ep);
        return;
    }
    if (ep != d->announce_ep) {
        return;
    }
    bool any = false;
    for (size_t i = 0; i < ARRAY_SIZE(dcp_services); i++) {
        if (d->only && strcmp(d->only, dcp_services[i].epic_name)) {
            continue;
        }
        if (!dcp_announce(d, ep, &dcp_services[i])) {
            return;
        }
        any = true;
        if (!d->announce_all && !d->only) {
            break;      /* default: the first service only */
        }
    }
    /*
     * A name that is not in the confirmed table is announced verbatim. This is
     * how you aim at a driver that matches on something other than EPICName --
     * notably AppleFirmwareKit's own AFKEchoTestEPIC, whose personality is
     * `IONameMatch = ["ap_echo-test"]` on AFKEndpointInterface, and which sends
     * traffic of its own accord, so it is the cheapest way to prove that a
     * driver really bound rather than merely that a nub appeared.
     */
    if (!any && d->only && !d->announce_dcpexpert) {
        DCPService synth = { d->only, d->only };
        any = dcp_announce(d, ep, &synth);
    }
    if (d->announce_dcpexpert) {
        if (dcp_announce_dcpexpert(d, ep)) {
            any = true;
        }
    }
    /*
     * One RBEP_RECV for the whole burst. RECV carries the new wptr and the AP
     * drains until rptr == wptr, so a single notify covers every entry -- and
     * one notify per entry overruns darwin_asc.c's inbound FIFO (16 announces
     * produced "asc(DCP): i2a fifo overflow, dropping ep 32", the dropped
     * message being the last and therefore the one that mattered; the guest
     * then stalled with the whole burst unread).
     */
    if (any) {
        darwin_afk_notify(d->afk, ep);
    }
}

/*
 * Received EPIC frames.
 *
 * Decoding is always on; replying is not. darwin_epic_describe() knows the
 * iOS 27 header shapes (8-byte message header + 16-byte packet header, see
 * darwin_epic.c), so we can always say what the guest sent.
 *
 * Whether to answer is a different question. Once the service announces are
 * accepted the AP opens an interface and issues a standard-service command
 * (type 0xc0), and it waits on that reply with a timeout -- so staying silent
 * guarantees a stall. But the body layout beyond its 8-byte header is not
 * derived yet: we know only that byte 1 is the command id the AP matches
 * replies against (bootkc 0xfffffff008b8eca8, `ubfx w1, w26, #8, #8`).
 *
 * So DARWIN_DCP_REPLY=1 turns on a deliberate *probe*: echo the command's
 * 8-byte body header back as a RESPONSE of the same type and interface, with
 * the rest of the body zeroed. This is a question we are asking the guest, not
 * modelled hardware behaviour -- it is off by default precisely because a
 * wrong reply is harder to read than no reply, and whatever the AP does next
 * is the evidence that tells us the real layout.
 */
static void dcp_afk_recv(void *opaque, uint8_t ep, uint32_t channel, uint32_t type,
                         const uint8_t *data, uint32_t len) {
    DarwinDCP *d = opaque;
    uint8_t state_reply[DARWIN_AFK_STATE_SIZE];

    if (darwin_afk_build_state_ack(channel, type, data, len, state_reply)) {
        bool sent = darwin_afk_send_qe(d->afk, ep, channel, type, state_reply,
                                      sizeof(state_reply), true);
        fprintf(stderr, "dcp: state ep 0x%02x seq %u request %u ack %u sent=%u\n",
                ep, lduw_le_p(data), ldl_le_p(data + 8),
                ldl_le_p(state_reply + 8), sent);
        return;
    }
    g_autofree char *desc = darwin_epic_describe(data, len);

    const char *probe = getenv("DARWIN_DCP_REPLY");
    bool want_reply = probe && probe[0] == '1';
    size_t hdrs = EPIC_MSG_HDR_SIZE + EPIC_PKT_HDR_SIZE;

    if (!want_reply || len < hdrs) {
        fprintf(stderr, "dcp: UNANSWERED EPIC frame ep 0x%02x qe(chan %u type %u len 0x%x): %s\n",
                ep, channel, type, len, desc);
        return;
    }

    const uint8_t *pkt = data + EPIC_MSG_HDR_SIZE;
    uint8_t cat = pkt[9], ptype = pkt[8];
    uint16_t iface = lduw_le_p(data + 2);
    uint32_t blen = len - hdrs;

    if (cat != EPIC_CAT_COMMAND || blen < 8) {
        fprintf(stderr, "dcp: EPIC frame ep 0x%02x (not a command, no reply): %s\n", ep, desc);
        return;
    }

    /*
     * Echo the command's 8-byte body header so the command id (byte 1) matches,
     * but *not* the u32 at +4, and zero everything after it.
     *
     * That u32 is the payload length on the way in -- across three commands in
     * one boot, arg was always body_len - 8 (0x60/0x68, 0x50/0x58, 0x90/0x98).
     * On the way back the AP reads the same offset as a return code: echoing it
     * made DCPAVRemoteSACControllerProxy, which is interface 8 and whose
     * command carried arg 0x50, report exactly
     *
     *   DCPAVRemoteSACControllerProxy::bootCompleteGated() error: ret = 0x50
     *
     * So we were handing our own request length back as a status. Zero is the
     * success value this hypothesis predicts; whatever the AP does next is the
     * evidence for or against it.
     */
    g_autofree uint8_t *body = g_malloc0(blen);
    memcpy(body, pkt + EPIC_PKT_HDR_SIZE, 4);

    size_t flen = 0;
    g_autofree uint8_t *frame =
        darwin_epic_build_call(iface, EPIC_CAT_RESPONSE, ptype, body, blen, 0, &flen);

    /*
     * Echo the first two bytes of the message header back.
     *
     * darwin_epic.c documents byte 0 as flags, "bit 0 means a 0x18-byte extra
     * block follows". That is not what this build does with it: across one
     * boot the AP sent 0x0, 0x1, 0x2 ... 0xf on successive frames, a clean
     * monotonic counter, so it is a sequence/tag the AP almost certainly
     * correlates replies against. Sending 0 in every reply, as we first did,
     * got DCPAVRemoteSACControllerProxy::bootCompleteGated() to parse the
     * response and reject it with ret = 0x50.
     */
    frame[0] = data[0];
    frame[1] = data[1];

    bool ok = darwin_afk_send_qe(d->afk, ep, 0, 0, frame, flen, true);
    fprintf(stderr, "dcp: PROBE reply ep 0x%02x -> RESPONSE type 0x%02x iface %u body 0x%x (%s): %s\n",
            ep, ptype, iface, (unsigned)blen, ok ? "queued" : "ring full", desc);
}

static const DarwinASCOps dcp_asc_ops = {
    .started = dcp_started,
    .ep_start = dcp_ep_start,
    .handle = dcp_handle,
};

static const DarwinAFKOps dcp_afk_ops = {
    .ep_started = dcp_afk_started,
    .recv = dcp_afk_recv,
};

DeviceState *darwin_dcp_create(struct dtree_node *dt_root, uint64_t iobase, DeviceState *aic) {
    struct dtree_node *dcp = adt_find_node(dt_root, "arm-io/dcp");
    if (!dcp || !adt_get_prop_val(dcp, "compatible")) {
        return NULL;
    }
    DarwinDCP *d = g_new0(DarwinDCP, 1);

    /*
     * Announce policy. Defaults: one service, the first of the confirmed
     * list, on endpoint 0x20 -- the smallest thing that can prove the framing
     * end to end. options=1 because that is the value the AP itself puts in
     * every report it sends (0xfffffff008b8fcbc, 0xfffffff008b8fe58); no
     * report path we traced reads it back, so it is the least-surprising
     * choice rather than a modelled behaviour.
     */
    const char *env = getenv("DARWIN_DCP_EPIC");
    d->announce = !(env && !strcmp(env, "off"));
    d->announce_all = env && !strcmp(env, "all");
    if (env && strcmp(env, "off") && strcmp(env, "all")) {
        d->only = env;
    }
    d->announce_ep = 0x20;
    if ((env = getenv("DARWIN_DCP_EPIC_EP"))) {
        d->announce_ep = (uint8_t)strtoul(env, NULL, 0);
    }
    d->options = 1;
    if ((env = getenv("DARWIN_DCP_EPIC_OPTIONS"))) {
        d->options = (uint8_t)strtoul(env, NULL, 0);
    }
    d->announce_dcpexpert = d->announce &&
        (!d->only || !strcmp(d->only, "dcpexpert-service"));
    d->next_iface = 1;

    memcpy(dcp_eps_adv, dcp_eps, sizeof(dcp_eps));
    dcp_eps_adv_n = ARRAY_SIZE(dcp_eps);
    const char *iomfb = getenv("DARWIN_DCP_IOMFB");
    if (iomfb && iomfb[0] && iomfb[0] != '0' && strcmp(iomfb, "off")) {
        dcp_eps_adv[dcp_eps_adv_n++] = 0x37;
        d->iomfb_level = (unsigned)strtoul(iomfb, NULL, 0);
        if (!d->iomfb_level) d->iomfb_level = 1;   /* "on", "yes", ... */
        fprintf(stderr, "dcp: advertising endpoint 0x37 (IOMFB link), level %u\n",
                d->iomfb_level);
    }
    d->asc = darwin_asc_create(dcp, iobase, aic, dcp_eps_adv, dcp_eps_adv_n, &dcp_asc_ops, d);

    /*
     * The AFK rings live in guest memory the DCP reaches through its own
     * DART. Which DART and which stream id is in the tree, not in this file:
     * /arm-io/dcp's "iommu-parent" phandle points at an iommu-mapper node
     * (/arm-io/dart-dcp/mapper-dcp on t8140) whose "reg" is the stream id.
     * Resolving it that way keeps this working if a future SoC renumbers.
     */
    struct dtree_node *dart_node = NULL;
    DeviceState *dart = NULL;
    unsigned sid = 0;
    if (darwin_afk_find_iommu(dt_root, dcp, &dart_node, &sid)) {
        const char *dart_name = adt_get_prop_val(dart_node, "name");
        dart = darwin_dart_find(dart_name);
        if (!dart) {
            fprintf(stderr, "dcp: device tree points at DART \"%s\" sid %u but no such "
                    "darwin-dart was created; AFK rings will be unreachable\n",
                    dart_name ? dart_name : "?", sid);
        } else {
            fprintf(stderr, "dcp: DMA through %s sid %u\n", dart_name, sid);
        }
    } else {
        fprintf(stderr, "dcp: no iommu-parent -> iommu-mapper chain in the device tree; "
                "AFK rings will be unreachable\n");
    }

    d->afk = darwin_afk_new(d->asc, adt_get_prop_val(dcp, "role"), dart, sid,
                            NULL, &dcp_afk_ops, d);
    g_assert(vmstate_register(NULL, 0, &vmstate_darwin_dcp, d) == 0);
    darwin_afk_register_vmstate(d->afk, 0);
    /*
     * The IOMFB link reaches the AP's RPC heap through the same DART and
     * stream id as the AFK rings -- both are DMA by the same coprocessor, and
     * the heap DVA the AP announces (0x10000000000) sits in the same IOVA
     * space the ring allocations come out of.
     */
    if (d->iomfb_level) {
        d->iomfb = darwin_iomfb_new(d->asc, dart, sid, d->iomfb_level);
        darwin_iomfb_register_vmstate(d->iomfb, 0);
    }
    for (size_t i = 0; i < ARRAY_SIZE(dcp_eps); i++) {
        darwin_afk_add_endpoint(d->afk, dcp_eps[i]);
    }

    if (!d->announce) {
        fprintf(stderr, "dcp: EPIC announces disabled (DARWIN_DCP_EPIC=off)\n");
    } else {
        fprintf(stderr, "dcp: will announce %s on ep 0x%02x (options 0x%02x)\n",
                d->announce_all ? "every confirmed service" :
                d->only ? d->only : dcp_services[0].epic_name,
                d->announce_ep, d->options);
    }
    return d->asc;
}
