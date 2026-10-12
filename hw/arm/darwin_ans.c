/*
 * darwin-ans: Apple ANS (NAND Storage) NVMe controller, t8140 / "M4+" flavour
 *
 * ANS is an RTKit coprocessor that fronts an NVMe controller. The RTKit half
 * needs nothing ANS-specific -- darwin_asc.c's generic handshake already
 * brings it up, and m1n1's own nvme_init() goes straight from rtkit_boot() to
 * plain MMIO (m1n1 src/nvme.c:369-379). This file is the NVMe half: the
 * register windows, Apple's tag-indexed submission path, and a QEMU block
 * backend underneath.
 *
 * The AP-side driver that wins the match on our kernelcache is
 * AppleANS3CGv2Controller (score 500000, observed in an io=0x1f probe:
 * "Found (ANS2) provider and coastguard").
 *
 * ---------------------------------------------------------------------------
 * WHERE THE REGISTERS LIVE (this corrects docs/re/ans-nvme-references.md 2.4)
 * ---------------------------------------------------------------------------
 * The reference notes could not decide, from Linux and m1n1 alone, whether the
 * NVMe registers are in /arm-io/ans reg[9] or reg[3], and flagged that
 * LINEAR_IOSQ_DB at +0x24910 does not fit inside reg[9]'s declared 0x10000.
 * Our own SPTM image settles it, because on this generation *SPTM* programs
 * the queue-base registers on XNU's behalf (via pmap_iommu_ioctl) and
 * therefore contains the mapping code. From nvme_bootstrap,
 * sptm:0xfffffff0270bec00..0xfffffff0270bec98 (firmware/sptm, __TEXT_EXEC
 * based at 0xfffffff027098000):
 *
 *   x24 = the node's raw "reg" array, 16 bytes per entry
 *   ldr x21,[x24,#0x38] / ldr x22,[x24,#0x30]   -> reg[3] len / base
 *   map_io(reg[3]) ; add x0,x0,#0x28000 ; map 1 page   -> instance+0xd50
 *   ...
 *   if (flags & nvme-secure-reg-layout)   BAR = reg[3] + 0x4000, 1 page
 *   else if (flags & nvme-secure-bar)     BAR = reg[9] + 0,      4 pages
 *                                         ldp x1,x2,[x24,#0x90] -> reg[9]
 *   instance+0xd80 = BAR
 *
 * So, for a node like ours that has "nvme-secure-bar" and not
 * "nvme-secure-reg-layout":
 *
 *   NVMe standard + Apple vendor registers   reg[9] + 0x0000 .. 0x10000
 *   NVMMU registers                          reg[3] + 0x28000 .. 0x2c000
 *
 * and the older "everything in reg[3]" layout survives as an alias: reg[3] +
 * 0x4000 is the same NVMe register file. That, not a +0x4000 shift inside one
 * window, is what the kernelcache's `mov w9,#0x1210 / mov w8,#0x5210 / csel`
 * is choosing between (0x5210 == 0x4000 + 0x1210). We back both, because it
 * costs nothing and because which one XNU uses is exactly the sort of thing
 * that changes between iOS versions.
 *
 * The linear-SQ block (0x24908/0x2490c/0x24910) is above reg[9]'s 0x10000, so
 * on this generation it must be reached through reg[3]. We accept it in either
 * window and log which one the guest actually used the first time -- that log
 * line is the empirical answer to section 2.4 and belongs in the notes.
 *
 * ---------------------------------------------------------------------------
 * REGISTER MAP
 * ---------------------------------------------------------------------------
 * NVMe file (reg[9] + off, or reg[3] + 0x4000 + off). Standard NVMe offsets
 * are Linux include/linux/nvme.h:132-162; Apple's are Linux
 * drivers/nvme/host/apple.c:42-54 and m1n1 src/nvme.c:36-49. Where SPTM writes
 * one, the SPTM address is given, and those writes are 32-bit halves, never a
 * single 64-bit store.
 *
 *   0x0000 CAP   (64) capabilities. Synthesised; no source states Apple's
 *                     real value. MQES/TO/DSTRD/CSS are read and branched on
 *                     by generic NVMe core code, so they must be sane.
 *   0x0008 VS    (32) version
 *   0x000c INTMS (32) interrupt mask set    0x0010 INTMC interrupt mask clear
 *   0x0014 CC    (32) EN bit0, SHN bits 15:14
 *   0x001c CSTS  (32) RDY bit0, CFS bit1, SHST bits 3:2
 *   0x0024 AQA   (32) ASQS | ACQS<<16   sptm:0xfffffff0270bd2a8
 *   0x0028 ASQ   (64) admin SQ base     sptm:0xfffffff0270bd344 / +0x2c
 *   0x0030 ACQ   (64) admin CQ base     sptm:0xfffffff0270bd3ec / +0x34
 *   0x1000 SQ0TDBL     standard SQ tail doorbell; only the pre-linear-sq
 *                      (t8015) path uses it. Logged, not acted on.
 *   0x1004 ACQ_DB      admin CQ *head* doorbell (write = new head)
 *   0x100c IOCQ_DB     IO CQ head doorbell
 *   0x1200 IOQ_SQ_BASE (64) IO SQ base, rewritten after CreateIOSQ.
 *                      sptm:0xfffffff0270bcdc8 / +0x1204.
 *   0x1208 IOQ_CQ_BASE (64) IO CQ base.  sptm:0xfffffff0270bcab4 / +0x120c.
 *                      m1n1 nvme.c:428-434 says the real ANS crashes without
 *                      these ("I/O SQ: 0x0" in its crashlog); we only record
 *                      them and cross-check them against the CreateIOxQ PRPs.
 *   0x1210 MAX_PEND_CMDS_CTRL  depth | depth<<16.  sptm:0xfffffff0270bd07c
 *   0x1300 BOOT_STATUS  reads 0xde71ce55 once the coprocessor is up. Polled
 *                      100000 times by IONVMeFamily before it gives up.
 *   0x1304 MODESEL     QAS-only, no other source. Storage, logged.
 *   0x1308 BASE_CMD_ID QAS-only and uncited there either. Storage, logged.
 *
 * Linear-SQ block (reg[3] + off, see above):
 *   0x24908 LINEAR_SQ_CTRL   bit0 EN
 *   0x2490c LINEAR_ASQ_DB    write the *tag* to submit admin cmds[tag]
 *   0x24910 LINEAR_IOSQ_DB   write the *tag* to submit IO cmds[tag]
 *
 * NVMMU block (reg[3] + off; SPTM maps exactly reg[3]+0x28000, one 16K page):
 *   0x28100 NUM_TCBS         queue depth - 1
 *   0x28108 ASQ_TCB_BASE (64) admin TCB array physical address
 *   0x28110 IOSQ_TCB_BASE(64) IO TCB array physical address
 *   0x28118 TCB_INVAL        write the tag of a completed command
 *   0x28120 TCB_STAT         Linux apple.c:60 says here, m1n1 nvme.c:55 says
 *   0x29120 TCB_STAT         here. Unresolved by either; we answer 0 (success)
 *                            at both and log which one the guest reads.
 *
 * ---------------------------------------------------------------------------
 * THE SUBMISSION PATH, WHICH IS THE ACTUAL DIVERGENCE FROM NVMe
 * ---------------------------------------------------------------------------
 * There is no submission ring. The driver writes the 64-byte SQE into
 * cmds[tag] -- an array indexed by tag, no head/tail, no wrap -- fills in a
 * matching 128-byte apple_nvmmu_tcb at tcbs[tag], and then writes *the tag
 * value* to LINEAR_ASQ_DB / LINEAR_IOSQ_DB. Linux
 * apple_nvme_submit_cmd_t8103(), drivers/nvme/host/apple.c:328-363; m1n1
 * nvme.c:219-302. Completion is a normal NVMe CQE, but the tag cannot be
 * reused until the driver writes it to TCB_INVAL (apple.c:297-305) -- a step
 * that is not in the NVMe spec at all, and that we accept and ignore.
 *
 * Admin and IO share one tag space capped at 64 (apple.c:62-71), and the whole
 * controller has exactly one IO queue pair (apple.c:1194).
 *
 * SQE stride: Linux and m1n1 both use a 64-byte struct nvme_command, and that
 * is our default. It is a property ("sqe-stride") because SPTM's own
 * sptm_nvme_set_sq_entry copies *128*-byte entries between its shadow and live
 * arrays (sptm:0xfffffff0270bc290, `add x24,x10,x21,lsl #7`), which is either
 * the TCB size (apple_nvmmu_tcb is 128 bytes) or evidence that this generation
 * widened the SQE. We could not tell statically. The first admin submission
 * hexdumps the queue so the log answers it; flip DARWIN_ANS_SQE_STRIDE=128 if
 * the opcodes only make sense at that spacing.
 *
 * ---------------------------------------------------------------------------
 * WHAT IS DELIBERATELY NOT MODELLED
 * ---------------------------------------------------------------------------
 * - AEN. The controller does not support it (apple.c:68-69). An Async Event
 *   Request is completed with Invalid Opcode rather than left outstanding, so
 *   the driver does not leak a tag.
 * - More than one IO queue pair, CMB/PMR, namespace management, Compare.
 * - The inline-crypto part of the TCB (offset 0x38 aes_iv, 0x40 64 unknown
 *   bytes) and the SHA/CoastGuard registers behind SPTM_NVME_ENDPOINTID_SHA_REG
 *   -- our node has no "nvme-ans-sha-present", so nothing should reach them.
 * - Namespaces other than the first. Our /arm-io/ans "namespaces" property
 *   lists seven (nsids 1,2,3,4,5,8,13); a real iPhone puts NVRAM, effaceable
 *   storage and the panic log in the others. Identify Namespace on any nsid we
 *   do not back returns the all-zero "inactive" answer NVMe defines for that
 *   case, and logs. If the driver turns out to require them, that log is where
 *   you will see it.
 * - SART enforcement. darwin_sart_allows() is consulted and violations are
 *   logged, but the transfer still happens unless DARWIN_ANS_SART=enforce.
 *   SART is an allow-list for real DMA; refusing a transfer because our
 *   understanding of who programmed the filter is wrong would look like a disk
 *   error, which is far harder to read than a log line.
 *
 * Block I/O is synchronous (blk_pread/blk_pwrite straight from the doorbell
 * write). NVMe drivers must tolerate a completion that is already posted when
 * the doorbell store retires. This also serializes storage requests with SMP;
 * DARWIN_ANS_PROFILE measures its cost without per-register tracing.
 *
 * Tracing: DARWIN_ANS_DEBUG=1 logs every register access with the register
 * decoded and every command with its arguments; DARWIN_ANS_DEBUG=2 adds
 * hexdumps of SQEs, TCBs and completions.
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/module.h"
#include "qemu/error-report.h"
#include "migration/vmstate.h"
#include "qemu/units.h"
#include "qemu/timer.h"
#include "hw/core/sysbus.h"
#include "hw/core/irq.h"
#include "hw/core/qdev-properties.h"
#include "hw/core/qdev-properties-system.h"
#include "system/block-backend.h"
#include "system/blockdev.h"
#include "system/memory.h"
#include "system/address-spaces.h"
#include "system/dma.h"
#include "system/system.h"
#include "xnu/boot/xnuboot.h"
#include "xnu/apple_dtree.h"
#include "xnu/darwin_aic.h"
#include "xnu/darwin_asc.h"
#include "xnu/darwin_sart.h"
#include "xnu/darwin_ans.h"

OBJECT_DECLARE_SIMPLE_TYPE(DarwinANSState, DARWIN_ANS)

/* ---------------- register offsets ---------------- */

/* NVMe standard, Linux include/linux/nvme.h:132-162 */
#define NVME_REG_CAP        0x0000
#define NVME_REG_VS         0x0008
#define NVME_REG_INTMS      0x000c
#define NVME_REG_INTMC      0x0010
#define NVME_REG_CC         0x0014
#define NVME_REG_CSTS       0x001c
#define NVME_REG_NSSR       0x0020
#define NVME_REG_AQA        0x0024
#define NVME_REG_ASQ        0x0028
#define NVME_REG_ACQ        0x0030
#define NVME_REG_CMBLOC     0x0038
#define NVME_REG_CMBSZ      0x003c
#define NVME_REG_DBS        0x1000

#define NVME_CC_EN          BIT(0)
#define NVME_CC_MPS_SHIFT   7
#define NVME_CC_SHN_SHIFT   14
#define NVME_CSTS_RDY       BIT(0)
#define NVME_CSTS_CFS       BIT(1)
#define NVME_CSTS_SHST_SHIFT 2

/* Apple vendor, Linux drivers/nvme/host/apple.c:42-54, m1n1 src/nvme.c:36-49 */
#define ANS_ACQ_DB          0x1004
#define ANS_IOCQ_DB         0x100c
#define ANS_IOQ_SQ_BASE     0x1200      /* m1n1 nvme.c:45; SPTM 0xfffffff0270bcdc8 */
#define ANS_IOQ_CQ_BASE     0x1208      /* m1n1 nvme.c:46; SPTM 0xfffffff0270bcab4 */
#define ANS_MAX_PEND_CMDS   0x1210
#define ANS_BOOT_STATUS     0x1300
#define ANS_BOOT_STATUS_OK  0xde71ce55u
#define ANS_MODESEL         0x1304      /* QAS ans.c:59, unverified elsewhere */
#define ANS_BASE_CMD_ID     0x1308      /* QAS ans.c:55, uncited even there */

#define ANS_LINEAR_SQ_CTRL  0x24908
#define ANS_LINEAR_SQ_EN    BIT(0)
#define ANS_LINEAR_ASQ_DB   0x2490c
#define ANS_LINEAR_IOSQ_DB  0x24910

#define ANS_NVMMU_BASE      0x28000
#define ANS_NVMMU_NUM_TCBS  0x28100
#define ANS_NVMMU_ASQ_TCB   0x28108
#define ANS_NVMMU_IOSQ_TCB  0x28110
#define ANS_NVMMU_TCB_INVAL 0x28118
#define ANS_NVMMU_TCB_STAT  0x28120     /* Linux apple.c:60 */
#define ANS_NVMMU_TCB_STAT_M1N1 0x29120 /* m1n1 nvme.c:55 */

/* The legacy in-band NVMe register window inside reg[3]; see the header. */
#define ANS_INBAND_NVME_OFF 0x4000
#define ANS_INBAND_NVME_END 0x8000

/* NVMe admin opcodes */
#define NVME_ADM_DELETE_SQ  0x00
#define NVME_ADM_CREATE_SQ  0x01
#define NVME_ADM_GET_LOG    0x02
#define NVME_ADM_DELETE_CQ  0x04
#define NVME_ADM_CREATE_CQ  0x05
#define NVME_ADM_IDENTIFY   0x06
#define NVME_ADM_ABORT      0x08
#define NVME_ADM_SET_FEAT   0x09
#define NVME_ADM_GET_FEAT   0x0a
#define NVME_ADM_ASYNC_EV   0x0c
/* Apple vendor admin opcode. Not in the NVMe spec and in none of the reference
 * bodies; observed being issued twice per boot by the code the guest calls
 * ProcessTunnelCommand / GetSanitizeCounters. See ans_admin(). */
#define ANS_ADM_VENDOR_TUNNEL 0xd8
/* Tunnel sub-command at args+0xc; see ans_admin(). */
#define ANS_TUNNEL_SET_TIME   6

/* Apple NVRAM namespace. AppleEmbeddedNVMeNVRAM uses a hardcoded NSID 255
 * (not one of the DT-listed namespaces) for its 8192-byte NVRAM region:
 * restore issues READ nsid 255, LBA 0, 2 blocks (2 x 4096 = 8192).
 * Backed by a small in-memory buffer, zero-initialized (fresh NVRAM). */
#define ANS_NVRAM_NSID 255
#define ANS_NVRAM_SIZE 8192

/* NVMe IO opcodes */
#define NVME_IO_FLUSH       0x00
#define NVME_IO_WRITE       0x01
#define NVME_IO_READ        0x02
#define NVME_IO_WRITE_ZERO  0x08
#define NVME_IO_DSM         0x09

/* status: (SCT << 8) | SC, as it sits in CQE DW3 bits 15:1 after our shift */
#define NVME_SC_SUCCESS         0x0000
#define NVME_SC_INVALID_OPCODE  0x0001
#define NVME_SC_INVALID_FIELD   0x0002
#define NVME_SC_DATA_XFER_ERR   0x0004
#define NVME_SC_INTERNAL        0x0006
#define NVME_SC_LBA_RANGE       0x0080
#define NVME_SC_INVALID_NS      0x000b
#define NVME_SC_CQ_INVALID      0x0100  /* SCT 1 (command specific) SC 0x00 */
#define NVME_SC_QID_INVALID     0x0101
#define NVME_SC_QSIZE_INVALID   0x0102

#define ANS_MAX_TAGS            256     /* the DT says 64; be generous */
#define ANS_SQE_SIZE            64
#define ANS_CQE_SIZE            16
#define ANS_TCB_SIZE            128
#define ANS_IDENTIFY_SIZE       4096

/* One 64-byte NVMe SQE, decoded. Field offsets are the NVMe 1.4 common
 * command format; we keep the raw bytes too for logging. */
typedef struct {
    uint8_t  opcode;
    uint8_t  flags;
    uint16_t cid;
    uint32_t nsid;
    uint64_t mptr;
    uint64_t prp1;
    uint64_t prp2;
    uint32_t cdw10, cdw11, cdw12, cdw13, cdw14, cdw15;
    uint8_t  raw[ANS_SQE_SIZE];
} ANSCmd;

/*
 * One of the "other" ANS register windows -- the ones ans-nvme-references
 * section 1 lists as unresolved. They now have names, from the REQUIRE strings
 * in AppleANS2NVMeController::start(), which maps device memory indices 4..9
 * into fAXI2AFDual / fANS2SLCommon / fANS2CCUSecurityINT / fANS2ParityWidget /
 * fANSSHABlock (IONVMeFamily+0xa9d8 onwards; the REQUIRE message strings are
 * at the kext's __cstring +0x218, +0x246, +0x278, +0x2f1, +0x34b).
 *
 * We back them as plain storage so they show up in our trace instead of
 * darwin-unimp's, with exactly one modelled register: see ANSAux.is_sl.
 */
typedef struct DarwinANSState DarwinANSState;
typedef struct {
    DarwinANSState *s;
    unsigned reg_index;
    MemoryRegion mr;
    uint32_t *store;
    uint32_t size;
    bool is_sl;
} ANSAux;

#define ANS_AUX_MAX 8
/* Stride between the per-SL register blocks inside reg[12]: SPTM indexes them
 * `ldr w6, [sl_base, sl_index << 16]` (sptm:0xfffffff0270bdafc). */
#define ANS_SL_STRIDE 0x10000

struct DarwinANSState {
    SysBusDevice parent_obj;
    MemoryRegion nvmmu_mr;      /* reg[3] */
    MemoryRegion nvme_mr;       /* reg[9] */
    ANSAux aux[ANS_AUX_MAX];
    unsigned n_aux;
    qemu_irq irq;

    /* properties */
    char *name;
    BlockBackend *blk;
    uint32_t nvmmu_size, nvme_size;
    uint32_t queue_entries;     /* "nvme-queue-entries" */
    uint32_t mqes;              /* CAP.MQES; 0 = same as queue_entries */
    uint32_t num_sl;            /* "nvme-num-sl" */
    uint32_t sl_idle_status;    /* what SL_STATUS reads; see ans_aux_read() */
    uint32_t nsid;              /* namespace we back with the block device */
    uint8_t nvram[ANS_NVRAM_SIZE]; /* NVRAM namespace (nsid 255) backing */
    uint32_t lba_size;
    uint32_t sqe_stride;
    uint32_t mdts;
    bool     blk_readonly;      /* the backend would not grant BLK_PERM_WRITE */
    bool     secure_bar;
    bool     linear_sq;
    char    *serial;
    char    *model;
    bool     boot_ready_at_reset;

    /* Host-only optional diagnostics, intentionally absent from VMState. */
    bool     profile;
    int64_t  profile_start_ns, profile_last_ns;
    uint64_t profile_count[4], profile_ns[4], profile_max_ns[4];

    /* unknown-offset backing storage, one array per window */
    uint32_t *nvmmu_store, *nvme_store;

    /* NVMe register state */
    uint64_t cap;
    uint32_t vs, cc, csts, aqa, intms;
    uint64_t asq, acq;
    uint64_t ioq_sq_base, ioq_cq_base;
    uint32_t max_pend_cmds;
    uint32_t linear_sq_ctrl;
    uint32_t modesel, base_cmd_id;
    bool     booted;            /* RTKit handshake done -> BOOT_STATUS reads OK */

    /* NVMMU register state */
    uint32_t num_tcbs;
    uint64_t asq_tcb_base, iosq_tcb_base;

    /* completion queues */
    uint32_t acq_head, acq_tail;
    bool     acq_phase;
    uint32_t iocq_head, iocq_tail;
    bool     iocq_phase;

    /* IO queue pair, from CreateIOCQ / CreateIOSQ */
    uint64_t iosq_addr, iocq_addr;
    uint16_t iosq_size, iocq_size;
    uint16_t iocq_id, iosq_id;
    bool     iosq_live, iocq_live, iocq_ien;

    /*
     * AppleSART's power-gate word for this block. /arm-io/sart-ans reg[2]
     * is the same physical window as our reg[3] (see the header), and the
     * kext polls "sart-power-reg-offset" (0x13e8) inside it: on the last
     * power release it writes 1 and sleeps 100 ms until it reads 1 back
     * (0xfffffff0094e7ef8-0xfffffff0094e7f1c, IOCoastGuardSARTMapper), on
     * power-up it writes 0 and waits for 0 (0xfffffff0094e7c24-0xfffffff0094e7c44).
     * 0x13e8 is below ANS_INBAND_NVME_OFF, so without this it decoded as an
     * NVMe register and never read back; with a native IORTC present,
     * IONVMeFamily's SendTimeToDevice takes and drops a power assertion
     * during controller start, the drop hit that poll, and the disk boot
     * idled forever before "BSD root" (probe RTC_NATIVE_SYS3, postmortem
     * thread at IONVMeFamily+0x4432c -> AppleSART+0xaa8).
     */
    uint32_t sart_power_off;    /* 0xffffffff: not present */
    uint32_t sart_power_word;

    /* diagnostics */
    DeviceState *sart;
    bool     sart_enforce;
    int      debug;
    bool     logged_linear_in_nvme, logged_linear_in_nvmmu;
    bool     logged_nvmmu_in_nvme, logged_inband_nvme, logged_nvme_in_nvmmu;
    bool     dumped_first_sqe;
    uint64_t n_admin, n_io, n_read_blocks, n_write_blocks;
    /* How many accesses the SART allow-list did not cover. Always every access
     * on t8140; see ans_sart_check() for why, and why we only log a few. */
    uint64_t n_sart_denied;
};

/* ---------------- small helpers ---------------- */

/* Bring-up scaffold; see the DARWIN_ANS_SELFWIRE section at the end of this file. */
static bool ans_selfwire(void)
{
    return getenv("DARWIN_ANS_SELFWIRE") != NULL;
}
static void ans_selfwire_retire_generic_asc(void);

static void ans_log(DarwinANSState *s, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "ans(%s): ", s->name ? s->name : "?");
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

static void ans_hexdump(DarwinANSState *s, const char *what, const uint8_t *p, size_t len)
{
    g_autoptr(GString) g = g_string_new(NULL);
    for (size_t i = 0; i < len; i++) {
        g_string_append_printf(g, "%s%02x", (i && !(i & 15)) ? "\n ans:   " : " ", p[i]);
    }
    ans_log(s, "%s (0x%zx bytes):%s\n", what, len, g->str);
}

/* Page size the guest chose in CC.MPS. NVMe: 2^(12 + MPS). */
static uint64_t ans_page_size(DarwinANSState *s)
{
    uint32_t mps = (s->cc >> NVME_CC_MPS_SHIFT) & 0xf;
    return 1ULL << (12 + mps);
}

/* ---------------- guest memory, through the SART allow-list ---------------- */

static void ans_sart_check(DarwinANSState *s, uint64_t pa, uint64_t len, const char *what)
{
    if (!s->sart) {
        return;
    }
    if (darwin_sart_allows(s->sart, pa, len)) {
        return;
    }
    /*
     * On t8140 this fires for *every* access, because the SART region table
     * never gets programmed through the MMIO window darwin_sart.c backs. That
     * is consistent with what the kernelcache says the CoastGuard mapper does:
     * `IOCoastGuardSARTMapper` reaches the filter through
     * "pmap_iommu_ioctl(&_ppl->super, SART_IOCTL_SET_ACTIVE, ...)"
     * (string in com.apple.driver.AppleSART) rather than by storing to
     * CONFIG/PADDR/SIZE, so nothing we can observe ever populates the table and
     * darwin_sart_allows() can only ever answer false.
     *
     * One boot of the real system volume produced 411,000 of these lines
     * (probe tag A9ROOT5, 186,596 of them for PRP-list pages alone), which
     * buries everything else in the trace, so print the first few and then only
     * a periodic running total. The full stream is still available with
     * DARWIN_ANS_DEBUG.
     *
     * Real hardware would drop the transfer. We log by default: see the file
     * header for why refusing looks like a disk error rather than a bug. */
    s->n_sart_denied++;
    if (s->debug || s->n_sart_denied <= 4 ||
        (s->n_sart_denied % 100000) == 0) {
        ans_log(s, "SART does not allow %s at 0x%" PRIx64 "+0x%" PRIx64
                "%s (%" PRIu64 " so far; the CoastGuard mapper programs the "
                "filter through pmap_iommu_ioctl, not this window, so the "
                "region table we can see is always empty)\n",
                what, pa, len, s->sart_enforce ? " (DENIED)" : " (allowing anyway)",
                s->n_sart_denied);
    }
}

static bool ans_dma(DarwinANSState *s, uint64_t pa, void *buf, size_t len,
                    bool to_guest, const char *what)
{
    ans_sart_check(s, pa, len, what);
    if (s->sart_enforce && s->sart && !darwin_sart_allows(s->sart, pa, len)) {
        return false;
    }
    MemTxResult r = address_space_rw(&address_space_memory, pa,
                                     MEMTXATTRS_UNSPECIFIED, buf, len, to_guest);
    if (r != MEMTX_OK) {
        ans_log(s, "DMA %s 0x%" PRIx64 "+0x%zx (%s) failed: %d\n",
                to_guest ? "write" : "read", pa, len, what, r);
        return false;
    }
    return true;
}

/*
 * Walk a PRP1/PRP2 pair and move `len` bytes.
 *
 * Standard NVMe (1.4 section 4.3): PRP1 may be offset within a page; PRP2 is
 * either the second (and last) page, or -- when more than two pages are needed
 * -- a pointer to a PRP list whose final entry chains to the next list if the
 * transfer does not fit. Nothing Apple-specific here; the TCB carries a copy of
 * PRP1/PRP2 that the NVMMU validates, which we accept and ignore.
 */
static bool ans_prp_rw(DarwinANSState *s, uint64_t prp1, uint64_t prp2,
                       uint8_t *buf, size_t len, bool to_guest)
{
    uint64_t ps = ans_page_size(s);
    size_t done = 0;

    if (!len) {
        return true;
    }
    uint64_t off = prp1 & (ps - 1);
    size_t chunk = MIN(len, ps - off);
    if (!ans_dma(s, prp1, buf, chunk, to_guest, "prp1")) {
        return false;
    }
    done += chunk;
    if (done == len) {
        return true;
    }

    if (len - done <= ps) {
        /* Exactly one more page: PRP2 is that page, not a list. */
        return ans_dma(s, prp2, buf + done, len - done, to_guest, "prp2");
    }

    /* PRP2 points at a list of page addresses. */
    uint64_t list = prp2;
    unsigned per_page = ps / 8;
    unsigned idx = 0;
    while (done < len) {
        uint64_t entry = 0;
        if (idx == per_page - 1 && len - done > ps) {
            /* Last slot chains to the next list page. */
            if (!ans_dma(s, list + (uint64_t)idx * 8, &entry, 8, false, "prp list link")) {
                return false;
            }
            list = le64_to_cpu(entry);
            idx = 0;
            continue;
        }
        if (!ans_dma(s, list + (uint64_t)idx * 8, &entry, 8, false, "prp list")) {
            return false;
        }
        entry = le64_to_cpu(entry);
        chunk = MIN(len - done, ps);
        if (!ans_dma(s, entry, buf + done, chunk, to_guest, "prp list page")) {
            return false;
        }
        done += chunk;
        idx++;
    }
    return true;
}

/* ---------------- completion ---------------- */

static void ans_update_irq(DarwinANSState *s)
{
    /*
     * One AIC line serves both completion queues ("nvme-interrupt-idx" picks
     * the 5th entry of the node's "interrupts"; Linux requests exactly one IRQ
     * and polls both queues from it, apple.c:707-723). Level semantics: high
     * while either queue has a CQE the driver has not acknowledged with its
     * head doorbell.
     */
    bool pending = (s->acq_tail != s->acq_head) || (s->iocq_tail != s->iocq_head);
    /*
     * INTMS/INTMC are the standard NVMe interrupt mask set/clear pair, one bit
     * per vector; we have one vector, so bit 0. Honouring them is not optional:
     * with the mask ignored, the driver's ISR masked the interrupt, found the
     * line still asserted on the way out, and wrote INTMS 22,590,248 times in
     * one boot.
     */
    bool masked = s->intms & BIT(0);
    qemu_set_irq(s->irq, pending && !masked);
}

/* Number of entries in the admin queues. AQA is *not* the spec's 0-based
 * ASQS/ACQS here: the guest writes 0x00400040 for a 64-entry pair, the same
 * count-not-0-based convention CAP.MQES and MAX_PEND_CMDS_CTRL use on this
 * hardware (all three observed in one boot). Treating it as 0-based would put
 * the 65th CQE one entry past the end of the guest's allocation. */
static uint32_t ans_asq_entries(DarwinANSState *s) { return s->aqa & 0xfff; }
static uint32_t ans_acq_entries(DarwinANSState *s) { return (s->aqa >> 16) & 0xfff; }

static void ans_post_cqe(DarwinANSState *s, bool admin, uint16_t cid,
                         uint16_t status, uint32_t result)
{
    uint64_t base = admin ? s->acq : s->iocq_addr;
    uint32_t size = admin ? ans_acq_entries(s) : s->iocq_size;
    uint32_t *tail = admin ? &s->acq_tail : &s->iocq_tail;
    bool *phase = admin ? &s->acq_phase : &s->iocq_phase;
    uint16_t sqid = admin ? 0 : s->iosq_id;

    if (!base || !size) {
        ans_log(s, "cannot post %s completion for cid %u: queue not set up "
                "(base 0x%" PRIx64 " size %u)\n",
                admin ? "admin" : "io", cid, base, size);
        return;
    }

    uint8_t cqe[ANS_CQE_SIZE];
    memset(cqe, 0, sizeof(cqe));
    stl_le_p(cqe + 0, result);
    /* DW2: SQ head (we consume immediately, so head == tail == 0 is honest
     * enough for a linear SQ, which has no head/tail at all) | SQ id. */
    stw_le_p(cqe + 8, 0);
    stw_le_p(cqe + 10, sqid);
    stw_le_p(cqe + 12, cid);
    stw_le_p(cqe + 14, (uint16_t)((status << 1) | (*phase ? 1 : 0)));

    uint64_t slot = base + (uint64_t)(*tail) * ANS_CQE_SIZE;
    ans_dma(s, slot, cqe, sizeof(cqe), true, admin ? "admin cqe" : "io cqe");

    if (s->debug > 1) {
        ans_hexdump(s, admin ? "admin CQE" : "io CQE", cqe, sizeof(cqe));
    }
    if (s->debug) {
        ans_log(s, "%s completion cid %u status 0x%04x result 0x%08x -> slot %u "
                "at 0x%" PRIx64 " phase %d\n",
                admin ? "admin" : "io", cid, status, result, *tail, slot, *phase);
    }

    *tail = (*tail + 1) % size;
    if (*tail == 0) {
        *phase = !*phase;
    }
    ans_update_irq(s);
}

/* ---------------- identify data ---------------- */

static void ans_str_pad(uint8_t *dst, size_t n, const char *src)
{
    /* NVMe identify strings are ASCII, space padded, not NUL terminated. */
    memset(dst, ' ', n);
    if (src) {
        size_t l = strlen(src);
        memcpy(dst, src, MIN(l, n));
    }
}

static int64_t ans_nsze(DarwinANSState *s)
{
    if (!s->blk) {
        return 0;
    }
    int64_t bytes = blk_getlength(s->blk);
    if (bytes < 0) {
        return 0;
    }
    return bytes / s->lba_size;
}

static void ans_identify_ctrl(DarwinANSState *s, uint8_t *buf)
{
    memset(buf, 0, ANS_IDENTIFY_SIZE);
    stw_le_p(buf + 0x00, 0x106b);           /* VID: Apple */
    stw_le_p(buf + 0x02, 0x106b);           /* SSVID */
    ans_str_pad(buf + 0x04, 20, s->serial);
    ans_str_pad(buf + 0x18, 40, s->model);
    ans_str_pad(buf + 0x40, 8, "1.0");      /* FR */
    buf[0x48] = 0;                          /* RAB */
    buf[0x4d] = (uint8_t)s->mdts;           /* MDTS, 2^n * CAP.MPSMIN pages */
    stw_le_p(buf + 0x4e, 0);                /* CNTLID */
    stl_le_p(buf + 0x50, 0x00010400);       /* VER 1.4.0 */
    stw_le_p(buf + 0x100, 0);               /* OACS: no format/firmware/security */
    buf[0x102] = 3;                         /* ACL */
    buf[0x103] = 0;                         /* AERL: no async events (apple.c:68) */
    buf[0x104] = 0;                         /* FRMW */
    buf[0x105] = 0;                         /* LPA */
    buf[0x106] = 0;                         /* ELPE */
    buf[0x107] = 0;                         /* NPSS: one power state */
    buf[0x200] = 0x66;                      /* SQES: 64 bytes min and max */
    buf[0x201] = 0x44;                      /* CQES: 16 bytes min and max */
    stw_le_p(buf + 0x202, s->queue_entries);/* MAXCMD */
    stl_le_p(buf + 0x204, 1);               /* NN: one namespace */
    /* ONCS: DSM (bit 2) and Write Zeroes (bit 3). APFS trims. */
    stw_le_p(buf + 0x208, BIT(2) | BIT(3));
    buf[0x20c] = 0;                         /* FNA */
    buf[0x20d] = 1;                         /* VWC: volatile write cache present */
    stl_le_p(buf + 0x218, 0);               /* SGLS: PRP only */
    /* The power state descriptor table at 0x800 is left zeroed: NPSS says
     * there is one state, and nothing in the boot path reads its contents. */
}

static void ans_identify_ns(DarwinANSState *s, uint32_t nsid, uint8_t *buf)
{
    memset(buf, 0, ANS_IDENTIFY_SIZE);
    if (nsid == ANS_NVRAM_NSID) {
        /* NVRAM namespace: ANS_NVRAM_SIZE bytes. Report in LBAs. */
        uint64_t nlb = ANS_NVRAM_SIZE / s->lba_size;
        stq_le_p(buf + 0x00, nlb);             /* NSZE */
        stq_le_p(buf + 0x08, nlb);             /* NCAP */
        stq_le_p(buf + 0x10, nlb);             /* NUSE */
        /* LBAF0: MS=0, LBADS=log2(lba_size), RP=0 */
        stl_le_p(buf + 0x80, (uint32_t)ctz32(s->lba_size) << 16);
        return;
    }
    if (nsid != s->nsid || !s->blk) {
        /* NVMe 1.4 6.1.5: an inactive NSID returns all zeroes, which is how
         * the driver learns the namespace is not there. */
        return;
    }
    int64_t nsze = ans_nsze(s);
    stq_le_p(buf + 0x00, nsze);             /* NSZE */
    stq_le_p(buf + 0x08, nsze);             /* NCAP */
    stq_le_p(buf + 0x10, nsze);             /* NUSE */
    buf[0x18] = 0;                          /* NSFEAT */
    buf[0x19] = 0;                          /* NLBAF: 1 format (0-based) */
    buf[0x1a] = 0;                          /* FLBAS: format 0 */
    buf[0x1b] = 0;                          /* MC: no metadata */
    buf[0x1c] = 0;                          /* DPC */
    buf[0x1d] = 0;                          /* DPS */
    /* LBAF0: MS=0, LBADS=log2(lba_size), RP=0 */
    stl_le_p(buf + 0x80, (uint32_t)ctz32(s->lba_size) << 16);
}

/* ---------------- command execution ---------------- */

static void ans_decode_cmd(const uint8_t *raw, ANSCmd *c)
{
    memcpy(c->raw, raw, ANS_SQE_SIZE);
    c->opcode = raw[0];
    c->flags  = raw[1];
    c->cid    = lduw_le_p(raw + 2);
    c->nsid   = ldl_le_p(raw + 4);
    c->mptr   = ldq_le_p(raw + 16);
    c->prp1   = ldq_le_p(raw + 24);
    c->prp2   = ldq_le_p(raw + 32);
    c->cdw10  = ldl_le_p(raw + 40);
    c->cdw11  = ldl_le_p(raw + 44);
    c->cdw12  = ldl_le_p(raw + 48);
    c->cdw13  = ldl_le_p(raw + 52);
    c->cdw14  = ldl_le_p(raw + 56);
    c->cdw15  = ldl_le_p(raw + 60);
}

static uint16_t ans_admin_identify(DarwinANSState *s, const ANSCmd *c, uint32_t *result)
{
    uint8_t cns = c->cdw10 & 0xff;
    g_autofree uint8_t *buf = g_malloc0(ANS_IDENTIFY_SIZE);

    switch (cns) {
    case 0x00:  /* Identify Namespace */
        ans_identify_ns(s, c->nsid, buf);
        if (c->nsid != s->nsid) {
            ans_log(s, "Identify Namespace for nsid %u, which we do not back "
                    "(only nsid %u has a block device) -- returning inactive\n",
                    c->nsid, s->nsid);
        }
        break;
    case 0x01:  /* Identify Controller */
        ans_identify_ctrl(s, buf);
        break;
    case 0x02:  /* Active Namespace ID list */
        stl_le_p(buf, s->blk ? s->nsid : 0);
        break;
    case 0x03: {
        /* Namespace Identification Descriptor list. One descriptor: NIDT 3
         * (UUID) would need a real UUID, so use NIDT 2 (NGUID) built from the
         * Apple vendor id and the nsid, which is stable and unique enough. */
        buf[0] = 0x02;          /* NIDT = NGUID */
        buf[1] = 0x10;          /* NIDL = 16 */
        buf[4] = 0x00; buf[5] = 0x00; buf[6] = 0x10; buf[7] = 0x6b;
        stl_be_p(buf + 4 + 12, s->nsid);
        break;
    }
    default:
        ans_log(s, "Identify CNS 0x%02x is not modelled; returning zeroes\n", cns);
        break;
    }
    *result = 0;
    if (!ans_prp_rw(s, c->prp1, c->prp2, buf, ANS_IDENTIFY_SIZE, true)) {
        return NVME_SC_DATA_XFER_ERR;
    }
    return NVME_SC_SUCCESS;
}

static uint16_t ans_admin_create_cq(DarwinANSState *s, const ANSCmd *c, uint32_t *result)
{
    uint16_t qid = c->cdw10 & 0xffff;
    uint16_t qsize = ((c->cdw10 >> 16) & 0xffff) + 1;
    bool pc = c->cdw11 & BIT(0);
    bool ien = c->cdw11 & BIT(1);

    *result = 0;
    if (!qid || qid > 1) {
        /* One IO queue pair only (apple.c:1194). */
        ans_log(s, "CreateIOCQ for qid %u refused: we model a single IO queue pair\n", qid);
        return NVME_SC_QID_INVALID;
    }
    if (!pc) {
        ans_log(s, "CreateIOCQ without PC (physically contiguous); we do not "
                "model scattered queues\n");
        return NVME_SC_INVALID_FIELD;
    }
    s->iocq_id = qid;
    s->iocq_addr = c->prp1;
    s->iocq_size = qsize;
    s->iocq_ien = ien;
    s->iocq_head = s->iocq_tail = 0;
    s->iocq_phase = true;
    s->iocq_live = true;
    ans_log(s, "IO CQ %u created: %u entries at 0x%" PRIx64 " (irq %s)\n",
            qid, qsize, s->iocq_addr, ien ? "enabled" : "disabled");
    return NVME_SC_SUCCESS;
}

static uint16_t ans_admin_create_sq(DarwinANSState *s, const ANSCmd *c, uint32_t *result)
{
    uint16_t qid = c->cdw10 & 0xffff;
    uint16_t qsize = ((c->cdw10 >> 16) & 0xffff) + 1;
    bool pc = c->cdw11 & BIT(0);
    uint16_t cqid = (c->cdw11 >> 16) & 0xffff;

    *result = 0;
    if (!qid || qid > 1) {
        ans_log(s, "CreateIOSQ for qid %u refused: we model a single IO queue pair\n", qid);
        return NVME_SC_QID_INVALID;
    }
    if (!s->iocq_live || cqid != s->iocq_id) {
        ans_log(s, "CreateIOSQ names CQ %u, which does not exist\n", cqid);
        return NVME_SC_CQ_INVALID;
    }
    if (!pc) {
        return NVME_SC_INVALID_FIELD;
    }
    s->iosq_id = qid;
    s->iosq_addr = c->prp1;
    s->iosq_size = qsize;
    s->iosq_live = true;
    ans_log(s, "IO SQ %u created: %u entries at 0x%" PRIx64 " -> CQ %u\n",
            qid, qsize, s->iosq_addr, cqid);
    return NVME_SC_SUCCESS;
}

static uint16_t ans_admin(DarwinANSState *s, const ANSCmd *c, uint32_t *result)
{
    *result = 0;
    switch (c->opcode) {
    case NVME_ADM_IDENTIFY:
        return ans_admin_identify(s, c, result);
    case NVME_ADM_CREATE_CQ:
        return ans_admin_create_cq(s, c, result);
    case NVME_ADM_CREATE_SQ:
        return ans_admin_create_sq(s, c, result);
    case NVME_ADM_DELETE_CQ:
        s->iocq_live = false;
        return NVME_SC_SUCCESS;
    case NVME_ADM_DELETE_SQ:
        s->iosq_live = false;
        return NVME_SC_SUCCESS;
    case NVME_ADM_SET_FEAT: {
        uint8_t fid = c->cdw10 & 0xff;
        if (fid == 0x07) {
            /* Number of Queues. Both fields are 0-based, so 0 means "one". */
            *result = 0;
            ans_log(s, "SetFeatures(Number of Queues) asked for %u SQ / %u CQ; "
                    "granting one of each\n",
                    (c->cdw11 & 0xffff) + 1, ((c->cdw11 >> 16) & 0xffff) + 1);
        } else if (s->debug) {
            ans_log(s, "SetFeatures fid 0x%02x cdw11 0x%08x accepted and ignored\n",
                    fid, c->cdw11);
        }
        return NVME_SC_SUCCESS;
    }
    case NVME_ADM_GET_FEAT: {
        uint8_t fid = c->cdw10 & 0xff;
        if (fid == 0x07) {
            *result = 0;        /* one SQ, one CQ */
        }
        return NVME_SC_SUCCESS;
    }
    case NVME_ADM_GET_LOG: {
        /* SMART / error / firmware pages: an all-zero page is a valid answer
         * for every one of them and nothing here branches on the contents. */
        uint32_t numd = ((c->cdw10 >> 16) & 0xfff) + 1;
        size_t len = (size_t)numd * 4;
        g_autofree uint8_t *buf = g_malloc0(len);
        if (!ans_prp_rw(s, c->prp1, c->prp2, buf, len, true)) {
            return NVME_SC_DATA_XFER_ERR;
        }
        return NVME_SC_SUCCESS;
    }
    case NVME_ADM_ABORT:
        *result = 1;            /* "the command was not aborted" */
        return NVME_SC_SUCCESS;
    case NVME_ADM_ASYNC_EV:
        /* See the header: this controller has no AEN, and leaving the command
         * outstanding would burn a tag out of a 64-deep shared space. */
        ans_log(s, "Async Event Request rejected: the ANS does not support AEN "
                "(Linux apple.c:68-69)\n");
        return NVME_SC_INVALID_OPCODE;
    case ANS_ADM_VENDOR_TUNNEL:
        /*
         * Apple's vendor "tunnel" command, used to pull firmware statistics out
         * of the coprocessor. Named from the guest's own reaction to us
         * refusing it (probe A9ROOT5, twice per boot):
         *
         *   AppleNVMeController::ProcessTunnelCommand():1227:
         *       nvme: ProcessTunnelCommand failed with status 0xe00002e9
         *   AppleANS2NVMeController::GetSanitizeCounters():5499:
         *       nvme: CORE_DEBUG_EXPORT_STATS failed with status 0xe00002e9
         *
         * Refusing it is *measured* to be non-fatal, which is why this stays an
         * honest hole rather than a fabricated answer: in probe tags A9LONG2
         * and A9FINAL the guest reaches
         * "(boot) Early boot complete. Continuing system boot." with these
         * rejections in the log, and the three AppleNVMe "Assert failed" lines
         * that follow each one are logging asserts -- execution continues past
         * them. The payload is real firmware state (sanitize counters, debug
         * statistics) we have no way to synthesise, and a zero-filled reply
         * would be a guess the driver might divide by.
         *
         * If a later boot stage does turn out to need it, complete it with a
         * zeroed buffer and say in the comment that the contents are a stub --
         * do not invent a layout.
         */
        /*
         * 2026-09-05, native RTC.  The SQE carries no PRP; probe
         * RTC_NATIVE_RESTORE5 dumped it as opcode d8, cid 6, cdw10 = 1,
         * cdw11 = 0x1c370000, cdw12 = 0x00000100: cdw12:cdw11 is the guest
         * physical address of the 4 KiB argument block (0x1001c370000, in
         * DRAM), and both tunnel commands of a boot reuse the same block.
         * AppleEmbeddedNVMeController::SendTimeToDevice (0xfffffff00a143d74)
         * writes sub-command 6 at +0xc (0xfffffff00a143e50), four clock
         * words at +0x1c..+0x33 (0xfffffff00a143e5c-0xfffffff00a143e64;
         * their meaning was not traced), and afterwards requires the u32 at
         * +0x4c to be zero (0xfffffff00a143e78) or it logs
         * "CORE_DEBUG_SET_TIME failed" and controller start stops before
         * AllocateNodes: probe RTC_NATIVE_SYS1 never reached "BSD root" with
         * the refusal.  The call only happens once a real IORTC exists
         * (0xfffffff00a143d9c/0xfffffff00a143da8), which is why the earlier
         * PV-RTC boots never saw it.  SET_TIME carries data to the device,
         * so completing it with status 0 invents nothing.
         */
        {
            uint8_t args[0x50] = { 0 };
            uint64_t args_pa = ((uint64_t)c->cdw12 << 32) | c->cdw11;
            bool have_args = args_pa && ans_prp_rw(s, args_pa, 0, args, sizeof(args), false);
            uint32_t sub = have_args ? ldl_le_p(args + 0xc) : 0xffffffff;
            if (have_args && sub == ANS_TUNNEL_SET_TIME) {
                stl_le_p(args + 0x4c, 0);
                if (!ans_prp_rw(s, args_pa, 0, args, sizeof(args), true)) {
                    return NVME_SC_DATA_XFER_ERR;
                }
                ans_log(s, "vendor tunnel command 0x%02x sub 6 (CORE_DEBUG_SET_TIME) accepted: "
                        "args+0x1c %08x %08x +0x24 0x%" PRIx64 " +0x2c 0x%" PRIx64
                        " (the driver's clock words; nothing here consumes them)\n",
                        c->opcode, ldl_le_p(args + 0x1c), ldl_le_p(args + 0x20),
                        ldq_le_p(args + 0x24), ldq_le_p(args + 0x2c));
                return NVME_SC_SUCCESS;
            }
            ans_log(s, "vendor tunnel command 0x%02x sub %u (CORE_DEBUG_EXPORT_STATS et al) "
                    "refused: the firmware statistics it wants are not modelled\n",
                    c->opcode, sub);
            if (s->debug) {
                ans_hexdump(s, "vendor tunnel SQE", c->raw, ANS_SQE_SIZE);
                if (have_args) {
                    ans_hexdump(s, "vendor tunnel args", args, sizeof(args));
                }
            }
        }
        return NVME_SC_INVALID_OPCODE;
    default:
        ans_log(s, "UNMODELLED admin opcode 0x%02x (cid %u nsid %u "
                "cdw10..12 %08x %08x %08x) -> Invalid Opcode\n",
                c->opcode, c->cid, c->nsid, c->cdw10, c->cdw11, c->cdw12);
        if (s->debug) {
            ans_hexdump(s, "unmodelled admin SQE", c->raw, ANS_SQE_SIZE);
        }
        return NVME_SC_INVALID_OPCODE;
    }
}

static uint16_t ans_io_command(DarwinANSState *s, const ANSCmd *c, uint32_t *result)
{
    *result = 0;

    if (c->opcode == NVME_IO_FLUSH) {
        if (s->blk && !s->blk_readonly) {
            blk_flush(s->blk);
        }
        return NVME_SC_SUCCESS;
    }
    if (c->opcode == NVME_IO_DSM) {
        /* Dataset Management / deallocate. Discarding is optional; treating it
         * as a no-op is always correct, just less tidy on the host. */
        return NVME_SC_SUCCESS;
    }

    bool is_write = (c->opcode == NVME_IO_WRITE);
    bool is_read = (c->opcode == NVME_IO_READ);
    bool is_wz = (c->opcode == NVME_IO_WRITE_ZERO);
    if (!is_write && !is_read && !is_wz) {
        ans_log(s, "UNMODELLED io opcode 0x%02x (cid %u) -> Invalid Opcode\n",
                c->opcode, c->cid);
        if (s->debug) {
            ans_hexdump(s, "unmodelled io SQE", c->raw, ANS_SQE_SIZE);
        }
        return NVME_SC_INVALID_OPCODE;
    }

    if ((is_write || is_wz) && s->blk_readonly) {
        /*
         * The NVMe status for this is "Attempted Write to Read Only Range",
         * but the sources here disagree on its encoding and we have never seen
         * the guest react to one, so report a plain Internal Error rather than
         * guess a code. The log is the real answer.
         */
        ans_log(s, "Write to a read-only backing image refused (cid %u lba %u); "
                "drop readonly=on, or pass a qcow2 overlay\n", c->cid, c->cdw10);
        return NVME_SC_INTERNAL;
    }

    if (!s->blk) {
        ans_log(s, "io opcode 0x%02x with no block backend attached; "
                "pass -drive if=none,id=ans,file=...\n", c->opcode);
        return NVME_SC_INTERNAL;
    }
    if (c->nsid == ANS_NVRAM_NSID) {
        /* NVRAM namespace: bounds-checked access to the in-memory buffer.
         * Reads return the stored bytes (zeroed when fresh); writes persist
         * for the life of the VM. This is what a real device with empty
         * NVRAM does, minus the flash wear. */
        uint64_t slba = ((uint64_t)c->cdw11 << 32) | c->cdw10;
        uint32_t nlb = (c->cdw12 & 0xffff) + 1;
        uint64_t off = slba * s->lba_size;
        uint64_t len = (uint64_t)nlb * s->lba_size;
        if (off + len > ANS_NVRAM_SIZE) {
            ans_log(s, "NVRAM nsid 255: slba %" PRIu64 " nlb %u runs past %u bytes\n",
                    slba, nlb, ANS_NVRAM_SIZE);
            return NVME_SC_LBA_RANGE;
        }
        if (is_wz) {
            memset(s->nvram + off, 0, len);
        } else if (is_write) {
            if (!ans_prp_rw(s, c->prp1, c->prp2, s->nvram + off, len, false)) {
                return NVME_SC_DATA_XFER_ERR;
            }
        } else { /* is_read */
            if (!ans_prp_rw(s, c->prp1, c->prp2, s->nvram + off, len, true)) {
                return NVME_SC_DATA_XFER_ERR;
            }
        }
        return NVME_SC_SUCCESS;
    }
    if (c->nsid != s->nsid) {
        return NVME_SC_INVALID_NS;
    }

    uint64_t slba = ((uint64_t)c->cdw11 << 32) | c->cdw10;
    uint32_t nlb = (c->cdw12 & 0xffff) + 1;
    uint64_t off = slba * s->lba_size;
    uint64_t len = (uint64_t)nlb * s->lba_size;
    int64_t total = blk_getlength(s->blk);

    if (total < 0 || (int64_t)(off + len) > total) {
        ans_log(s, "LBA range: slba %" PRIu64 " nlb %u runs past the %" PRId64
                "-byte backing image\n", slba, nlb, total);
        return NVME_SC_LBA_RANGE;
    }

    if (is_wz) {
        if (blk_pwrite_zeroes(s->blk, off, len, 0) < 0) {
            return NVME_SC_DATA_XFER_ERR;
        }
        s->n_write_blocks += nlb;
        return NVME_SC_SUCCESS;
    }

    g_autofree uint8_t *buf = g_malloc(len);
    if (is_read) {
        if (blk_pread(s->blk, off, len, buf, 0) < 0) {
            ans_log(s, "host read of 0x%" PRIx64 "+0x%" PRIx64 " failed\n", off, len);
            return NVME_SC_DATA_XFER_ERR;
        }
        if (!ans_prp_rw(s, c->prp1, c->prp2, buf, len, true)) {
            return NVME_SC_DATA_XFER_ERR;
        }
        s->n_read_blocks += nlb;
    } else {
        if (!ans_prp_rw(s, c->prp1, c->prp2, buf, len, false)) {
            return NVME_SC_DATA_XFER_ERR;
        }
        if (blk_pwrite(s->blk, off, len, buf, 0) < 0) {
            ans_log(s, "host write of 0x%" PRIx64 "+0x%" PRIx64 " failed\n", off, len);
            return NVME_SC_DATA_XFER_ERR;
        }
        s->n_write_blocks += nlb;
    }
    if (s->debug) {
        ans_log(s, "%s cid %u nsid %u lba %" PRIu64 " x%u (0x%" PRIx64
                " bytes) prp %" PRIx64 "/%" PRIx64 "\n",
                is_read ? "READ " : "WRITE", c->cid, c->nsid, slba, nlb, len,
                c->prp1, c->prp2);
    }
    return NVME_SC_SUCCESS;
}

static uint16_t ans_io(DarwinANSState *s, const ANSCmd *c, uint32_t *result)
{
    if (!s->profile) {
        return ans_io_command(s, c, result);
    }
    int kind = c->opcode == NVME_IO_READ ? 0 :
               c->opcode == NVME_IO_WRITE || c->opcode == NVME_IO_WRITE_ZERO ? 1 :
               c->opcode == NVME_IO_FLUSH ? 2 : 3;
    int64_t start = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
    uint16_t status = ans_io_command(s, c, result);
    int64_t now = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
    uint64_t elapsed = now - start;
    s->profile_count[kind]++;
    s->profile_ns[kind] += elapsed;
    s->profile_max_ns[kind] = MAX(s->profile_max_ns[kind], elapsed);
    if (now - s->profile_last_ns >= NANOSECONDS_PER_SECOND) {
        static const char *const names[] = {"read", "write", "flush", "other"};
        /* Cumulative wall time includes allocation, DMA and the complete
         * synchronous block call, not just physical host disk latency. */
        ans_log(s, "PROFILE elapsed_ns=%" PRId64
                " read_bytes=%" PRIu64 " write_bytes=%" PRIu64,
                now - s->profile_start_ns,
                s->n_read_blocks * s->lba_size,
                s->n_write_blocks * s->lba_size);
        for (int i = 0; i < 4; i++) {
            fprintf(stderr, " %s_count=%" PRIu64 " %s_ns=%" PRIu64
                    " %s_max_ns=%" PRIu64,
                    names[i], s->profile_count[i], names[i], s->profile_ns[i],
                    names[i], s->profile_max_ns[i]);
        }
        fputc('\n', stderr);
        s->profile_last_ns = now;
    }
    return status;
}

/*
 * A tag was written to LINEAR_ASQ_DB / LINEAR_IOSQ_DB. Fetch cmds[tag], run
 * it, post a CQE.
 */
static void ans_submit(DarwinANSState *s, bool admin, uint32_t tag)
{
    uint64_t base = admin ? s->asq : s->iosq_addr;
    uint64_t tcbs = admin ? s->asq_tcb_base : s->iosq_tcb_base;
    const char *which = admin ? "ASQ" : "IOSQ";

    if (!(s->csts & NVME_CSTS_RDY)) {
        ans_log(s, "%s doorbell tag %u while the controller is not ready "
                "(CC 0x%08x CSTS 0x%08x)\n", which, tag, s->cc, s->csts);
        return;
    }
    if (!base) {
        ans_log(s, "%s doorbell tag %u but the queue base is still 0\n", which, tag);
        return;
    }
    if (tag >= s->queue_entries) {
        ans_log(s, "%s doorbell tag %u is past the %u-entry queue\n",
                which, tag, s->queue_entries);
        return;
    }

    uint8_t raw[ANS_SQE_SIZE];
    uint64_t slot = base + (uint64_t)tag * s->sqe_stride;
    if (!ans_dma(s, slot, raw, sizeof(raw), false, "sqe")) {
        return;
    }

    /*
     * First submission of each kind: dump enough of the queue and its TCB
     * array to settle the 64-vs-128 byte stride question from the header, and
     * to show what the NVMMU was actually handed.
     */
    if (!s->dumped_first_sqe && s->debug) {
        s->dumped_first_sqe = true;
        uint8_t probe[256];
        if (ans_dma(s, base, probe, sizeof(probe), false, "sq probe")) {
            ans_hexdump(s, "first 0x100 bytes of the submission queue", probe, sizeof(probe));
        }
        if (tcbs && ans_dma(s, tcbs, probe, sizeof(probe), false, "tcb probe")) {
            ans_hexdump(s, "first 0x100 bytes of the TCB array", probe, sizeof(probe));
        }
    }

    ANSCmd c;
    ans_decode_cmd(raw, &c);

    if (s->debug) {
        ans_log(s, "%s tag %u -> opcode 0x%02x cid %u nsid %u "
                "prp %016" PRIx64 "/%016" PRIx64 " cdw10 %08x cdw11 %08x cdw12 %08x\n",
                which, tag, c.opcode, c.cid, c.nsid, c.prp1, c.prp2,
                c.cdw10, c.cdw11, c.cdw12);
    }
    if (s->debug > 1) {
        ans_hexdump(s, "SQE", raw, sizeof(raw));
        if (tcbs) {
            uint8_t tcb[ANS_TCB_SIZE];
            if (ans_dma(s, tcbs + (uint64_t)tag * ANS_TCB_SIZE, tcb, sizeof(tcb),
                        false, "tcb")) {
                ans_hexdump(s, "TCB", tcb, sizeof(tcb));
            }
        }
    }

    uint32_t result = 0;
    uint16_t status;
    if (admin) {
        s->n_admin++;
        status = ans_admin(s, &c, &result);
    } else {
        s->n_io++;
        status = ans_io(s, &c, &result);
    }
    ans_post_cqe(s, admin, c.cid, status, result);
}

/* ---------------- controller enable / disable ---------------- */

static void ans_cc_write(DarwinANSState *s, uint32_t val)
{
    bool was_en = s->cc & NVME_CC_EN;
    bool now_en = val & NVME_CC_EN;
    uint32_t shn = (val >> NVME_CC_SHN_SHIFT) & 3;

    s->cc = val;

    if (now_en && !was_en) {
        s->acq_head = s->acq_tail = 0;
        s->acq_phase = true;
        s->csts |= NVME_CSTS_RDY;
        s->csts &= ~NVME_CSTS_CFS;
        ans_log(s, "controller enabled: AQA 0x%08x (ASQ %u / ACQ %u entries) "
                "ASQ 0x%" PRIx64 " ACQ 0x%" PRIx64 " page size 0x%" PRIx64 "\n",
                s->aqa, ans_asq_entries(s), ans_acq_entries(s),
                s->asq, s->acq, ans_page_size(s));
    } else if (!now_en && was_en) {
        s->csts &= ~NVME_CSTS_RDY;
        s->iosq_live = s->iocq_live = false;
        s->acq_head = s->acq_tail = 0;
        s->iocq_head = s->iocq_tail = 0;
        ans_update_irq(s);
        ans_log(s, "controller disabled\n");
    }
    if (shn) {
        /* Shutdown notification: report "shutdown complete" (SHST = 2). */
        s->csts = (s->csts & ~(3u << NVME_CSTS_SHST_SHIFT)) |
                  (2u << NVME_CSTS_SHST_SHIFT);
        if (s->blk) {
            blk_flush(s->blk);
        }
        ans_log(s, "shutdown notification %u; reporting shutdown complete\n", shn);
    }
}

/* ---------------- register decode ---------------- */

typedef enum {
    ANS_WIN_NVMMU = 0,          /* reg[3] */
    ANS_WIN_NVME  = 1,          /* reg[9] */
} ANSWindow;

typedef enum {
    ANS_BLK_NONE = 0,
    ANS_BLK_NVME,               /* offset is in the NVMe register file */
    ANS_BLK_LINEAR,             /* offset is in the linear-SQ block */
    ANS_BLK_NVMMU,              /* offset is in the NVMMU block */
} ANSBlock;

/*
 * Which logical register block an (window, offset) pair names, and the offset
 * within it. Both windows are decoded with the same table: the blocks do not
 * overlap in offset space, older SoCs really do put all of them in one window,
 * and answering in both is strictly safer than guessing. The first access that
 * arrives through the "wrong" window is logged, because that is the finding.
 */
static ANSBlock ans_decode(DarwinANSState *s, ANSWindow win, hwaddr off, hwaddr *reg)
{
    if (off >= ANS_NVMMU_BASE && off < ANS_NVMMU_BASE + 0x4000) {
        *reg = off;
        if (win == ANS_WIN_NVME && !s->logged_nvmmu_in_nvme) {
            s->logged_nvmmu_in_nvme = true;
            ans_log(s, "NOTE: NVMMU register 0x%05" HWADDR_PRIx " was reached through "
                    "reg[9] (the NVMe window), not reg[3]\n", off);
        }
        return ANS_BLK_NVMMU;
    }
    if (off == ANS_NVMMU_TCB_STAT_M1N1) {
        *reg = off;
        return ANS_BLK_NVMMU;
    }
    if (off >= ANS_LINEAR_SQ_CTRL && off <= ANS_LINEAR_IOSQ_DB) {
        *reg = off;
        if (win == ANS_WIN_NVME && !s->logged_linear_in_nvme) {
            s->logged_linear_in_nvme = true;
            ans_log(s, "NOTE: linear-SQ register 0x%05" HWADDR_PRIx " was reached "
                    "through reg[9]; its declared length is only 0x10000, so the "
                    "device tree understates the window (ans-nvme-references 2.4 (a))\n",
                    off);
        } else if (win == ANS_WIN_NVMMU && !s->logged_linear_in_nvmmu) {
            s->logged_linear_in_nvmmu = true;
            ans_log(s, "NOTE: linear-SQ register 0x%05" HWADDR_PRIx " was reached "
                    "through reg[3] (ans-nvme-references 2.4 (b) is the right reading)\n",
                    off);
        }
        return ANS_BLK_LINEAR;
    }
    if (off >= ANS_INBAND_NVME_OFF && off < ANS_INBAND_NVME_END) {
        /*
         * The +0x4000 alias. In reg[3] this is the window SPTM would have used
         * as the BAR had the node carried "nvme-secure-reg-layout"
         * (sptm:0xfffffff0270bec64), and it is the other half of the
         * kernelcache's `mov w9,#0x1210 / mov w8,#0x5210 / csel`. In reg[9] it
         * is what ans-nvme-references 2.2 proposed. Same registers either way.
         */
        *reg = off - ANS_INBAND_NVME_OFF;
        if (!s->logged_inband_nvme) {
            s->logged_inband_nvme = true;
            ans_log(s, "NOTE: NVMe register 0x%04" HWADDR_PRIx " reached through the "
                    "+0x4000 alias in reg[%d]\n",
                    off - ANS_INBAND_NVME_OFF, win == ANS_WIN_NVME ? 9 : 3);
        }
        return ANS_BLK_NVME;
    }
    if (off < ANS_INBAND_NVME_OFF) {
        /*
         * The NVMe register file, answered in *both* windows. This is not
         * hedging: on t8140 the two halves of the driver really do use
         * different windows for the same registers.
         *
         *   - XNU's IONVMeFamily uses reg[3]. Observed: with the model
         *     answering only in reg[9], the guest polled reg[3]+0x1300
         *     (BOOT_STATUS) 38461 times and got 0, and never issued another
         *     access. That is the m1n1 NVME_T8103 "one window for everything"
         *     layout (src/nvme.c:311-338), on a node m1n1's own test puts in
         *     the NVME_T8132 family.
         *   - SPTM uses reg[9], because nvme_bootstrap picked reg[9] as the BAR
         *     for a node with "nvme-secure-bar" (sptm:0xfffffff0270bec78,
         *     `ldp x1, x2, [x24, #0x90]` = reg[9]) and writes AQA/ASQ/ACQ and
         *     the IO queue bases through it.
         *
         * Since it is one controller, both windows share one register state.
         * That is the answer to ans-nvme-references 2.4: not (a) or (b), both.
         */
        *reg = off;
        if (win == ANS_WIN_NVMMU && !s->logged_nvme_in_nvmmu) {
            s->logged_nvme_in_nvmmu = true;
            ans_log(s, "NOTE: NVMe register 0x%04" HWADDR_PRIx " reached through reg[3], "
                    "the flat/T8103-style layout (ans-nvme-references 2.4)\n", off);
        }
        return ANS_BLK_NVME;
    }
    return ANS_BLK_NONE;
}

static const char *ans_reg_name(ANSBlock blk, hwaddr reg)
{
    if (blk == ANS_BLK_NVME) {
        switch (reg) {
        case NVME_REG_CAP:      return "CAP";
        case NVME_REG_CAP + 4:  return "CAP_HI";
        case NVME_REG_VS:       return "VS";
        case NVME_REG_INTMS:    return "INTMS";
        case NVME_REG_INTMC:    return "INTMC";
        case NVME_REG_CC:       return "CC";
        case NVME_REG_CSTS:     return "CSTS";
        case NVME_REG_NSSR:     return "NSSR";
        case NVME_REG_AQA:      return "AQA";
        case NVME_REG_ASQ:      return "ASQ_LO";
        case NVME_REG_ASQ + 4:  return "ASQ_HI";
        case NVME_REG_ACQ:      return "ACQ_LO";
        case NVME_REG_ACQ + 4:  return "ACQ_HI";
        case NVME_REG_DBS:      return "SQ0TDBL";
        case ANS_ACQ_DB:        return "ACQ_DB";
        case ANS_IOCQ_DB:       return "IOCQ_DB";
        case ANS_IOQ_SQ_BASE:   return "IOQ_SQ_BASE_LO";
        case ANS_IOQ_SQ_BASE+4: return "IOQ_SQ_BASE_HI";
        case ANS_IOQ_CQ_BASE:   return "IOQ_CQ_BASE_LO";
        case ANS_IOQ_CQ_BASE+4: return "IOQ_CQ_BASE_HI";
        case ANS_MAX_PEND_CMDS: return "MAX_PEND_CMDS_CTRL";
        case ANS_BOOT_STATUS:   return "BOOT_STATUS";
        case ANS_MODESEL:       return "MODESEL";
        case ANS_BASE_CMD_ID:   return "BASE_CMD_ID";
        }
        return "nvme?";
    }
    if (blk == ANS_BLK_LINEAR) {
        switch (reg) {
        case ANS_LINEAR_SQ_CTRL: return "LINEAR_SQ_CTRL";
        case ANS_LINEAR_ASQ_DB:  return "LINEAR_ASQ_DB";
        case ANS_LINEAR_IOSQ_DB: return "LINEAR_IOSQ_DB";
        }
        return "linear?";
    }
    if (blk == ANS_BLK_NVMMU) {
        switch (reg) {
        case ANS_NVMMU_NUM_TCBS:    return "NUM_TCBS";
        case ANS_NVMMU_ASQ_TCB:     return "ASQ_TCB_BASE_LO";
        case ANS_NVMMU_ASQ_TCB + 4: return "ASQ_TCB_BASE_HI";
        case ANS_NVMMU_IOSQ_TCB:    return "IOSQ_TCB_BASE_LO";
        case ANS_NVMMU_IOSQ_TCB + 4:return "IOSQ_TCB_BASE_HI";
        case ANS_NVMMU_TCB_INVAL:   return "TCB_INVAL";
        case ANS_NVMMU_TCB_STAT:    return "TCB_STAT(linux)";
        case ANS_NVMMU_TCB_STAT_M1N1: return "TCB_STAT(m1n1)";
        }
        return "nvmmu?";
    }
    return "?";
}

/* Compose a 64-bit register out of 32-bit halves, because SPTM writes both
 * ASQ/ACQ and the IO queue bases as two 32-bit stores
 * (sptm:0xfffffff0270bd344 and 0xfffffff0270bcdc8). */
static void ans_put_half(uint64_t *dst, bool high, uint32_t val)
{
    if (high) {
        *dst = (*dst & 0x00000000ffffffffULL) | ((uint64_t)val << 32);
    } else {
        *dst = (*dst & 0xffffffff00000000ULL) | val;
    }
}

/* ---------------- MMIO ---------------- */

static uint64_t ans_read_block(DarwinANSState *s, ANSBlock blk, hwaddr reg, unsigned size)
{
    switch (blk) {
    case ANS_BLK_NVME:
        switch (reg) {
        case NVME_REG_CAP:      return size == 8 ? s->cap : (uint32_t)s->cap;
        case NVME_REG_CAP + 4:  return s->cap >> 32;
        case NVME_REG_VS:       return s->vs;
        case NVME_REG_INTMS:
        case NVME_REG_INTMC:    return s->intms;
        case NVME_REG_CC:       return s->cc;
        case NVME_REG_CSTS:     return s->csts;
        case NVME_REG_AQA:      return s->aqa;
        case NVME_REG_ASQ:      return size == 8 ? s->asq : (uint32_t)s->asq;
        case NVME_REG_ASQ + 4:  return s->asq >> 32;
        case NVME_REG_ACQ:      return size == 8 ? s->acq : (uint32_t)s->acq;
        case NVME_REG_ACQ + 4:  return s->acq >> 32;
        case ANS_IOQ_SQ_BASE:   return (uint32_t)s->ioq_sq_base;
        case ANS_IOQ_SQ_BASE+4: return s->ioq_sq_base >> 32;
        case ANS_IOQ_CQ_BASE:   return (uint32_t)s->ioq_cq_base;
        case ANS_IOQ_CQ_BASE+4: return s->ioq_cq_base >> 32;
        case ANS_MAX_PEND_CMDS: return s->max_pend_cmds;
        case ANS_BOOT_STATUS:   return s->booted ? ANS_BOOT_STATUS_OK : 0;
        case ANS_MODESEL:       return s->modesel;
        case ANS_BASE_CMD_ID:   return s->base_cmd_id;
        /* Doorbells are write-only on real hardware; read back what we hold. */
        case ANS_ACQ_DB:        return s->acq_head;
        case ANS_IOCQ_DB:       return s->iocq_head;
        }
        break;
    case ANS_BLK_LINEAR:
        if (reg == ANS_LINEAR_SQ_CTRL) {
            return s->linear_sq_ctrl;
        }
        return 0;               /* the two doorbells are write-only */
    case ANS_BLK_NVMMU:
        switch (reg) {
        case ANS_NVMMU_NUM_TCBS:     return s->num_tcbs;
        case ANS_NVMMU_ASQ_TCB:      return (uint32_t)s->asq_tcb_base;
        case ANS_NVMMU_ASQ_TCB + 4:  return s->asq_tcb_base >> 32;
        case ANS_NVMMU_IOSQ_TCB:     return (uint32_t)s->iosq_tcb_base;
        case ANS_NVMMU_IOSQ_TCB + 4: return s->iosq_tcb_base >> 32;
        case ANS_NVMMU_TCB_STAT:
        case ANS_NVMMU_TCB_STAT_M1N1:
            /* Both Linux (apple.c:302-304) and m1n1 (nvme.c:272-274) only
             * warn when this is non-zero; nothing depends on a failure being
             * reportable, so we always say "fine". */
            return 0;
        }
        break;
    default:
        break;
    }
    return 0;
}

static void ans_write_block(DarwinANSState *s, ANSBlock blk, hwaddr reg,
                            uint64_t val, unsigned size)
{
    switch (blk) {
    case ANS_BLK_NVME:
        switch (reg) {
        case NVME_REG_INTMS: s->intms |= (uint32_t)val; ans_update_irq(s); return;
        case NVME_REG_INTMC: s->intms &= ~(uint32_t)val; ans_update_irq(s); return;
        case NVME_REG_CC:    ans_cc_write(s, (uint32_t)val); return;
        case NVME_REG_AQA:   s->aqa = (uint32_t)val; return;
        case NVME_REG_ASQ:
            if (size == 8) { s->asq = val; } else { ans_put_half(&s->asq, false, val); }
            return;
        case NVME_REG_ASQ + 4: ans_put_half(&s->asq, true, val); return;
        case NVME_REG_ACQ:
            if (size == 8) { s->acq = val; } else { ans_put_half(&s->acq, false, val); }
            return;
        case NVME_REG_ACQ + 4: ans_put_half(&s->acq, true, val); return;
        case ANS_ACQ_DB:
            s->acq_head = (uint32_t)val;
            ans_update_irq(s);
            return;
        case ANS_IOCQ_DB:
            s->iocq_head = (uint32_t)val;
            ans_update_irq(s);
            return;
        case ANS_IOQ_SQ_BASE:
            if (size == 8) { s->ioq_sq_base = val; } else { ans_put_half(&s->ioq_sq_base, false, val); }
            return;
        case ANS_IOQ_SQ_BASE + 4:
            ans_put_half(&s->ioq_sq_base, true, val);
            if (s->iosq_live && s->ioq_sq_base != s->iosq_addr) {
                ans_log(s, "IOQ_SQ_BASE 0x%" PRIx64 " disagrees with the CreateIOSQ "
                        "PRP1 0x%" PRIx64 "; trusting IOQ_SQ_BASE\n",
                        s->ioq_sq_base, s->iosq_addr);
                s->iosq_addr = s->ioq_sq_base;
            } else if (!s->iosq_live && s->ioq_sq_base) {
                /* m1n1 nvme.c:428-434 writes these after CreateIOSQ; if we see
                 * them first, keep the value so the queue still works. */
                s->iosq_addr = s->ioq_sq_base;
            }
            return;
        case ANS_IOQ_CQ_BASE:
            if (size == 8) { s->ioq_cq_base = val; } else { ans_put_half(&s->ioq_cq_base, false, val); }
            return;
        case ANS_IOQ_CQ_BASE + 4:
            ans_put_half(&s->ioq_cq_base, true, val);
            if (s->iocq_live && s->ioq_cq_base != s->iocq_addr) {
                ans_log(s, "IOQ_CQ_BASE 0x%" PRIx64 " disagrees with the CreateIOCQ "
                        "PRP1 0x%" PRIx64 "; trusting IOQ_CQ_BASE\n",
                        s->ioq_cq_base, s->iocq_addr);
                s->iocq_addr = s->ioq_cq_base;
            } else if (!s->iocq_live && s->ioq_cq_base) {
                s->iocq_addr = s->ioq_cq_base;
            }
            return;
        case ANS_MAX_PEND_CMDS:
            s->max_pend_cmds = (uint32_t)val;
            ans_log(s, "MAX_PEND_CMDS_CTRL = 0x%08x (%u | %u<<16)\n",
                    (uint32_t)val, (uint32_t)val & 0xffff, (uint32_t)(val >> 16) & 0xffff);
            return;
        case NVME_REG_DBS:
            /* Only the pre-linear-SQ (t8015) path uses this; if it ever fires
             * here, the driver decided we are an older ANS and the linear path
             * below will never be used. */
            ans_log(s, "SQ0TDBL written (0x%" PRIx64 ") -- that is the t8015 "
                    "non-linear-sq submission path, which we do not model\n", val);
            return;
        case ANS_MODESEL:     s->modesel = (uint32_t)val; return;
        case ANS_BASE_CMD_ID: s->base_cmd_id = (uint32_t)val; return;
        case ANS_BOOT_STATUS:
            ans_log(s, "BOOT_STATUS written 0x%" PRIx64 " (read-only on hardware)\n", val);
            return;
        }
        break;

    case ANS_BLK_LINEAR:
        switch (reg) {
        case ANS_LINEAR_SQ_CTRL:
            s->linear_sq_ctrl = (uint32_t)val;
            ans_log(s, "LINEAR_SQ_CTRL = 0x%08x (EN %s)\n", (uint32_t)val,
                    (val & ANS_LINEAR_SQ_EN) ? "set" : "clear");
            return;
        case ANS_LINEAR_ASQ_DB:
            ans_submit(s, true, (uint32_t)val);
            return;
        case ANS_LINEAR_IOSQ_DB:
            ans_submit(s, false, (uint32_t)val);
            return;
        }
        break;

    case ANS_BLK_NVMMU:
        switch (reg) {
        case ANS_NVMMU_NUM_TCBS:
            s->num_tcbs = (uint32_t)val;
            ans_log(s, "NUM_TCBS = %u (queue depth %u)\n", (uint32_t)val, (uint32_t)val + 1);
            return;
        case ANS_NVMMU_ASQ_TCB:
            if (size == 8) { s->asq_tcb_base = val; } else { ans_put_half(&s->asq_tcb_base, false, val); }
            return;
        case ANS_NVMMU_ASQ_TCB + 4: ans_put_half(&s->asq_tcb_base, true, val); return;
        case ANS_NVMMU_IOSQ_TCB:
            if (size == 8) { s->iosq_tcb_base = val; } else { ans_put_half(&s->iosq_tcb_base, false, val); }
            return;
        case ANS_NVMMU_IOSQ_TCB + 4: ans_put_half(&s->iosq_tcb_base, true, val); return;
        case ANS_NVMMU_TCB_INVAL:
            /* The tag can be reused now. We never held it, so nothing to do;
             * this exists so the write is not logged as an unknown offset. */
            if (s->debug > 1) {
                ans_log(s, "TCB_INVAL tag %u\n", (uint32_t)val);
            }
            return;
        }
        break;
    default:
        break;
    }
}

static uint64_t ans_mmio_read(void *opaque, hwaddr off, unsigned size, ANSWindow win)
{
    DarwinANSState *s = opaque;
    hwaddr reg = 0;
    uint64_t val;

    if (win == ANS_WIN_NVMMU && off == s->sart_power_off) {
        if (s->debug) {
            ans_log(s, "read  reg[3]+0x%05" HWADDR_PRIx " (SART power gate) -> 0x%x\n",
                    off, s->sart_power_word);
        }
        return s->sart_power_word;
    }
    ANSBlock blk = ans_decode(s, win, off, &reg);

    if (blk == ANS_BLK_NONE) {
        uint32_t *store = win == ANS_WIN_NVME ? s->nvme_store : s->nvmmu_store;
        uint32_t sz = win == ANS_WIN_NVME ? s->nvme_size : s->nvmmu_size;
        val = (off + 4 <= sz) ? store[off / 4] : 0;
    } else {
        val = ans_read_block(s, blk, reg, size);
    }

    if (s->debug) {
        ans_log(s, "read  reg[%d]+0x%05" HWADDR_PRIx " (%s) -> 0x%" PRIx64 "\n",
                win == ANS_WIN_NVME ? 9 : 3, off,
                blk == ANS_BLK_NONE ? "unknown" : ans_reg_name(blk, reg), val);
    }
    return val;
}

static void ans_mmio_write(void *opaque, hwaddr off, uint64_t val, unsigned size,
                           ANSWindow win)
{
    DarwinANSState *s = opaque;
    hwaddr reg = 0;

    if (win == ANS_WIN_NVMMU && off == s->sart_power_off) {
        ans_log(s, "SART power gate word <- 0x%" PRIx64 " (stored; AppleSART polls it back)\n", val);
        s->sart_power_word = (uint32_t)val;
        return;
    }
    ANSBlock blk = ans_decode(s, win, off, &reg);

    /*
     * The interrupt mask registers are written from the ISR on every
     * completion and, when something is wrong, in a tight loop; logging each
     * one produced a 22-million-line trace. Log them only when the mask
     * actually changes state.
     */
    bool mask_reg = (blk == ANS_BLK_NVME &&
                     (reg == NVME_REG_INTMS || reg == NVME_REG_INTMC));
    uint32_t intms_before = s->intms;

    if (s->debug && !mask_reg) {
        ans_log(s, "write reg[%d]+0x%05" HWADDR_PRIx " (%s) <- 0x%" PRIx64 "\n",
                win == ANS_WIN_NVME ? 9 : 3, off,
                blk == ANS_BLK_NONE ? "unknown" : ans_reg_name(blk, reg), val);
    }
    if (mask_reg) {
        ans_write_block(s, blk, reg, val, size);
        if (s->debug && s->intms != intms_before) {
            ans_log(s, "write reg[%d]+0x%05" HWADDR_PRIx " (%s) <- 0x%" PRIx64
                    " (mask now 0x%08x)\n", win == ANS_WIN_NVME ? 9 : 3, off,
                    ans_reg_name(blk, reg), val, s->intms);
        }
        return;
    }

    if (blk == ANS_BLK_NONE) {
        /* Unknown offsets remember writes and never fault: XNU treats a
         * synchronous external abort as a hardware error. */
        uint32_t *store = win == ANS_WIN_NVME ? s->nvme_store : s->nvmmu_store;
        uint32_t sz = win == ANS_WIN_NVME ? s->nvme_size : s->nvmmu_size;
        if (off + 4 <= sz) {
            store[off / 4] = (uint32_t)val;
        }
        return;
    }
    ans_write_block(s, blk, reg, val, size);
}

static uint64_t ans_nvmmu_read(void *o, hwaddr off, unsigned size)
{
    return ans_mmio_read(o, off, size, ANS_WIN_NVMMU);
}
static void ans_nvmmu_write(void *o, hwaddr off, uint64_t v, unsigned size)
{
    ans_mmio_write(o, off, v, size, ANS_WIN_NVMMU);
}
static uint64_t ans_nvme_read(void *o, hwaddr off, unsigned size)
{
    return ans_mmio_read(o, off, size, ANS_WIN_NVME);
}
static void ans_nvme_write(void *o, hwaddr off, uint64_t v, unsigned size)
{
    ans_mmio_write(o, off, v, size, ANS_WIN_NVME);
}

/*
 * The auxiliary windows. Everything here is plain storage except one register,
 * and that one register is load-bearing.
 *
 * SL_STATUS, reg[12] + sl_index * 0x10000 + 0x0
 * -----------------------------------------------
 * After every command the driver waits for the "SL" blocks to go idle, and it
 * does not do so over MMIO: it calls pmap_iommu_ioctl(nvme, 0x8025, ...) with
 * a 1-second deadline (IONVMeFamily+0x329ec, w1 = 0x8025, w3 = 24; the failure
 * message is "SL failed to idle after %llu us for cid %d"). SPTM services that
 * by polling, for each of "nvme-num-sl" blocks:
 *
 *   sptm:0xfffffff0270bdaf8   ldr  x6, [inst, #0xdc8]   ; reg[12] base
 *   sptm:0xfffffff0270bdafc   lsl  x7, x2, #16          ; sl_index * 0x10000
 *   sptm:0xfffffff0270bdb00   ldr  w6, [x6, x7]         ; SL_STATUS
 *   sptm:0xfffffff0270bdb08   bics wzr, w15, w6         ; w15 = 0x007f0000
 *   sptm:0xfffffff0270bdb14   bics wzr, w16, w6         ; w16 = 0x000000ff (other mode)
 *
 * `bics wzr, mask, val` is zero exactly when every bit of the mask is set in
 * the value, so "idle" means bits 16..22 are all set (or, in the mode selected
 * by the caller's flag bit 8, bits 0..7). Reading 0 -- which is what
 * darwin-unimp gave it -- means "never idle", and the boot stalled there with
 * the guest re-reading reg[12]+0x0 and reg[12]+0x10000 forever.
 *
 * We therefore answer 0x007f00ff, which satisfies both tests and nothing else
 * we can see. What the individual bits mean is not stated anywhere we can
 * read, so this is a "make the check pass" value, not a model; it is a
 * property so it can be changed without a rebuild.
 *
 * SPTM maps reg[12] as the SL block, and reg[10]/reg[11] alongside it
 * (sptm:0xfffffff0270bed24 / 0xfffffff0270bed54 / 0xfffffff0270bed84, reading
 * the reg array at +0xc0, +0xa0, +0xb0 = indices 12, 10, 11). It writes
 * 0x00800080 to reg[10]+0x4 once the SLs are idle
 * (sptm:0xfffffff0270bdb70-0xfffffff0270bdb78); we record that write and do
 * nothing with it, because nothing reads it back.
 */
static uint64_t ans_aux_read(void *opaque, hwaddr off, unsigned size)
{
    ANSAux *w = opaque;
    DarwinANSState *s = w->s;
    uint64_t val;
    const char *name = "";

    if (w->is_sl && (off % ANS_SL_STRIDE) == 0 && (off / ANS_SL_STRIDE) < s->num_sl) {
        val = s->sl_idle_status;
        name = " SL_STATUS";
    } else {
        val = (off + 4 <= w->size) ? w->store[off / 4] : 0;
    }
    if (s->debug) {
        ans_log(s, "read  reg[%u]+0x%05" HWADDR_PRIx "%s -> 0x%" PRIx64 "\n",
                w->reg_index, off, name, val);
    }
    return val;
}

static void ans_aux_write(void *opaque, hwaddr off, uint64_t val, unsigned size)
{
    ANSAux *w = opaque;
    DarwinANSState *s = w->s;

    if (s->debug) {
        ans_log(s, "write reg[%u]+0x%05" HWADDR_PRIx " <- 0x%" PRIx64 "\n",
                w->reg_index, off, val);
    }
    if (off + 4 <= w->size) {
        w->store[off / 4] = (uint32_t)val;
    }
}

static const MemoryRegionOps ans_aux_ops = {
    .read = ans_aux_read,
    .write = ans_aux_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl.min_access_size = 4,
    .impl.max_access_size = 4,
    .valid.min_access_size = 4,
    .valid.max_access_size = 8,
};

static const MemoryRegionOps ans_nvmmu_ops = {
    .read = ans_nvmmu_read,
    .write = ans_nvmmu_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl.min_access_size = 4,
    .impl.max_access_size = 8,
    .valid.min_access_size = 4,
    .valid.max_access_size = 8,
};

static const MemoryRegionOps ans_nvme_ops = {
    .read = ans_nvme_read,
    .write = ans_nvme_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl.min_access_size = 4,
    .impl.max_access_size = 8,
    .valid.min_access_size = 4,
    .valid.max_access_size = 8,
};

/* ---------------- device ---------------- */

static void darwin_ans_realize(DeviceState *dev, Error **errp)
{
    DarwinANSState *s = DARWIN_ANS(dev);

    if (!s->nvme_size || !s->nvmmu_size) {
        error_setg(errp, "darwin-ans: missing NVMe/NVMMU window size");
        return;
    }
    if (!s->queue_entries || s->queue_entries > ANS_MAX_TAGS) {
        error_setg(errp, "darwin-ans: nvme-queue-entries %u out of range",
                   s->queue_entries);
        return;
    }
    if (s->lba_size < 512 || (s->lba_size & (s->lba_size - 1))) {
        error_setg(errp, "darwin-ans: logical-block-size %u is not a power of two >= 512",
                   s->lba_size);
        return;
    }

    const char *d = getenv("DARWIN_ANS_DEBUG");
    s->debug = d ? (atoi(d) ? atoi(d) : 1) : 0;
    s->profile = getenv("DARWIN_ANS_PROFILE") != NULL;
    s->profile_start_ns = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
    s->profile_last_ns = s->profile_start_ns;
    const char *env = getenv("DARWIN_ANS_SQE_STRIDE");
    if (env) {
        s->sqe_stride = strtoul(env, NULL, 0);
    }
    /* See the "mdts" property: the guest's own PRP-list sizing bounds this from
     * below, and the bound is not stated anywhere, so it stays adjustable. */
    env = getenv("DARWIN_ANS_MDTS");
    if (env) {
        s->mdts = strtoul(env, NULL, 0);
    }
    env = getenv("DARWIN_ANS_SART");
    s->sart_enforce = env && !strcmp(env, "enforce");
    s->boot_ready_at_reset = getenv("DARWIN_ANS_BOOT_READY") != NULL;
    if (s->boot_ready_at_reset) {
        s->booted = true;
    }

    /*
     * Ask the block layer for write permission.
     *
     * DEFINE_PROP_DRIVE only attaches the backend; it does not grant anything.
     * Devices normally follow up with blkconf_apply_backend_options(), which
     * exists to parse a BlockConf we do not have, but whose only load-bearing
     * step for us is the blk_set_perm() at hw/block/block.c:226. Without it the
     * first guest write aborts the whole process, at the *end* of a five-minute
     * boot, with no hint that a device model is at fault:
     *
     *   ans(ans): IOSQ tag 19 -> opcode 0x01 cid 19 nsid 1 ...   (NVMe Write)
     *   Assertion failed: (child->perm & BLK_PERM_WRITE),
     *       function bdrv_co_write_req_prepare, file io.c, line 2016.
     *
     * Reads never trip it, which is why this survived a boot that mounts APFS
     * and reads the whole dyld shared cache: iOS mounts its system volume
     * read-only, so the first write in practice came from newfs_apfs run by
     * hand (probe scratch image, tag wtest).
     *
     * A backend the user opened read-only (-drive ...,readonly=on, or a
     * read-only file) is honoured rather than fought: we take read permission
     * only and refuse Writes in ans_io() instead of aborting.
     */
    if (s->blk) {
        s->blk_readonly = !blk_supports_write_perm(s->blk);
        uint64_t perm = BLK_PERM_CONSISTENT_READ;
        if (!s->blk_readonly) {
            perm |= BLK_PERM_WRITE;
        }
        if (blk_set_perm(s->blk, perm,
                         BLK_PERM_CONSISTENT_READ | BLK_PERM_WRITE_UNCHANGED,
                         errp) < 0) {
            return;
        }
        if (s->blk_readonly) {
            ans_log(s, "the backing image is read-only; NVMe Write, Write "
                    "Zeroes and Flush will be refused\n");
        }
    }

    s->nvmmu_store = g_new0(uint32_t, s->nvmmu_size / 4);
    s->nvme_store = g_new0(uint32_t, s->nvme_size / 4);

    /*
     * CAP. No public source states Apple's real value (ans-nvme-references 2.1
     * says so explicitly), but the guest told us one field of it exactly.
     *
     * MQES is **not** the 0-based value the NVMe spec defines. With
     * MQES = queue_entries - 1 = 0x3f, the very next thing that happened after
     * the driver read CAP was:
     *
     *   AppleANS2CGv2Controller::GetNVMeSPTMQueueEntries()::164: NVMe Queue Entries=64
     *   panic(...): [SPTM] VIOLATION_NVME_ILLEGAL_NVMe_QUEUE_ENTRIES_MISMATCH:
     *               validate_nvme_queue_entries(nvme_validation.h:182)
     *               - queue_entries(0x3f)
     *
     * i.e. IONVMeFamily read CAP, took the low 16 bits as the queue depth, and
     * handed 0x3f to SPTM, which compares it against the device tree's
     * "nvme-queue-entries" (0x40) and kills the boot on a mismatch. So on this
     * hardware CAP.MQES carries the entry *count*, and it has to agree with the
     * device tree. Hence mqes defaults to queue_entries, and both come from the
     * same property. The `mqes` qdev property exists so a future SoC that does
     * follow the spec here can be handled without a rebuild.
     *
     * The rest is synthesised to be the least surprising thing that passes
     * generic nvme_enable_ctrl()'s sanity checks:
     *   CQR      = 1, contiguous queues required (we model nothing else)
     *   TO       = 20, i.e. 10 s for CSTS.RDY to settle
     *   DSTRD    = 0, 4-byte doorbell stride (Apple's are at fixed offsets)
     *   CSS bit0 = the NVM command set
     *   MPSMIN   = 0 (4K), MPSMAX = 4 (64K) so a 16K-page guest is in range
     */
    if (!s->mqes) {
        s->mqes = s->queue_entries;
    }
    s->cap = (uint64_t)(s->mqes & 0xffff)
           | BIT_ULL(16)                        /* CQR */
           | ((uint64_t)20 << 24)               /* TO */
           | (1ULL << 37)                       /* CSS: NVM command set */
           | (0ULL << 48)                       /* MPSMIN */
           | (4ULL << 52);                      /* MPSMAX */
    s->vs = 0x00010400;                         /* 1.4.0 */
    s->acq_phase = s->iocq_phase = true;

    memory_region_init_io(&s->nvmmu_mr, OBJECT(s), &ans_nvmmu_ops, s,
                          "darwin-ans-nvmmu", s->nvmmu_size);
    memory_region_init_io(&s->nvme_mr, OBJECT(s), &ans_nvme_ops, s,
                          "darwin-ans-nvme", s->nvme_size);
    sysbus_init_mmio(SYS_BUS_DEVICE(dev), &s->nvmmu_mr);
    sysbus_init_mmio(SYS_BUS_DEVICE(dev), &s->nvme_mr);
    for (unsigned i = 0; i < s->n_aux; i++) {
        ANSAux *w = &s->aux[i];
        w->s = s;
        w->store = g_new0(uint32_t, w->size / 4);
        g_autofree char *nm = g_strdup_printf("darwin-ans-reg%u", w->reg_index);
        memory_region_init_io(&w->mr, OBJECT(s), &ans_aux_ops, w, nm, w->size);
        sysbus_init_mmio(SYS_BUS_DEVICE(dev), &w->mr);
    }
    sysbus_init_irq(SYS_BUS_DEVICE(dev), &s->irq);
}

static int darwin_ans_post_load(void *opaque, int version_id)
{
    DarwinANSState *s = opaque;
    uint32_t asz = ans_acq_entries(s);
    /*
     * CreateIO{S,C}Q encodes QSIZE as a zero-based value even though this
     * Apple generation exposes CAP.MQES and the DT queue depth as counts.
     * Consequently the observed legal maximum is queue_entries + 1 (65 on
     * t8140), while tag validation still uses the 64-entry DT tag space.
     */
    uint32_t io_queue_limit = s->queue_entries + 1;

    if (s->n_aux > ANS_AUX_MAX || asz > s->queue_entries ||
        (asz ? (s->acq_head >= asz || s->acq_tail >= asz) :
               (s->acq_head || s->acq_tail || (s->cc & NVME_CC_EN))) ||
        (s->iocq_live && (!s->iocq_size || s->iocq_head >= s->iocq_size ||
                          s->iocq_tail >= s->iocq_size)) ||
        (s->iosq_live && !s->iosq_size) ||
        s->iosq_size > io_queue_limit ||
        s->iocq_size > io_queue_limit ||
        (s->iocq_live && (s->iocq_id != 1 || !s->iocq_addr)) ||
        (s->iosq_live && (s->iosq_id != 1 || !s->iosq_addr))) {
        error_report("darwin-ans: invalid migrated queue state: aux=%u "
                     "acq=%u/%u/%u io-cq=%u/%u/%u live=%u "
                     "io-sq-size=%u live=%u max=%u",
                     s->n_aux, s->acq_head, s->acq_tail, asz,
                     s->iocq_head, s->iocq_tail, s->iocq_size,
                     s->iocq_live, s->iosq_size, s->iosq_live,
                     s->queue_entries);
        return -EINVAL;
    }

    /*
     * All commands execute synchronously in the doorbell MMIO callback, so
     * there is no host AIO request to recreate.  Re-drive the one level IRQ
     * from the restored producer/consumer indices and interrupt mask.
     */
    ans_update_irq(s);
    return 0;
}

/* Optional so that snapshots taken before the SART power word existed
 * still restore; it only appears once the kext has written the word. */
static bool ans_sart_power_needed(void *opaque)
{
    DarwinANSState *s = opaque;
    return s->sart_power_word != 0;
}

static const VMStateDescription vmstate_darwin_ans_sart_power = {
    .name = TYPE_DARWIN_ANS "/sart-power",
    .version_id = 1,
    .minimum_version_id = 1,
    .needed = ans_sart_power_needed,
    .fields = (const VMStateField[]) {
        VMSTATE_UINT32(sart_power_word, DarwinANSState),
        VMSTATE_END_OF_LIST()
    },
};

static const VMStateDescription vmstate_darwin_ans = {
    .name = TYPE_DARWIN_ANS,
    .version_id = 1,
    .minimum_version_id = 1,
    .post_load = darwin_ans_post_load,
    .fields = (const VMStateField[]) {
        VMSTATE_UINT32_EQUAL(nvmmu_size, DarwinANSState),
        VMSTATE_UINT32_EQUAL(nvme_size, DarwinANSState),
        VMSTATE_UINT32_EQUAL(queue_entries, DarwinANSState),
        VMSTATE_UINT32_EQUAL(n_aux, DarwinANSState),
        VMSTATE_UINT32_EQUAL(mqes, DarwinANSState),
        VMSTATE_UINT32_EQUAL(num_sl, DarwinANSState),
        VMSTATE_UINT32_EQUAL(sl_idle_status, DarwinANSState),
        VMSTATE_UINT32_EQUAL(nsid, DarwinANSState),
        VMSTATE_BUFFER(nvram, DarwinANSState),
        VMSTATE_UINT32_EQUAL(lba_size, DarwinANSState),
        VMSTATE_UINT32_EQUAL(sqe_stride, DarwinANSState),
        VMSTATE_UINT32_EQUAL(mdts, DarwinANSState),
        VMSTATE_UINT32_EQUAL(aux[0].size, DarwinANSState),
        VMSTATE_UINT32_EQUAL(aux[1].size, DarwinANSState),
        VMSTATE_UINT32_EQUAL(aux[2].size, DarwinANSState),
        VMSTATE_UINT32_EQUAL(aux[3].size, DarwinANSState),
        VMSTATE_UINT32_EQUAL(aux[4].size, DarwinANSState),
        VMSTATE_UINT32_EQUAL(aux[5].size, DarwinANSState),
        VMSTATE_UINT32_EQUAL(aux[6].size, DarwinANSState),
        VMSTATE_UINT32_EQUAL(aux[7].size, DarwinANSState),
        VMSTATE_VBUFFER_UINT32(nvmmu_store, DarwinANSState, 1, NULL,
                               nvmmu_size),
        VMSTATE_VBUFFER_UINT32(nvme_store, DarwinANSState, 1, NULL,
                               nvme_size),
        VMSTATE_VBUFFER_UINT32(aux[0].store, DarwinANSState, 1, NULL,
                               aux[0].size),
        VMSTATE_VBUFFER_UINT32(aux[1].store, DarwinANSState, 1, NULL,
                               aux[1].size),
        VMSTATE_VBUFFER_UINT32(aux[2].store, DarwinANSState, 1, NULL,
                               aux[2].size),
        VMSTATE_VBUFFER_UINT32(aux[3].store, DarwinANSState, 1, NULL,
                               aux[3].size),
        VMSTATE_VBUFFER_UINT32(aux[4].store, DarwinANSState, 1, NULL,
                               aux[4].size),
        VMSTATE_VBUFFER_UINT32(aux[5].store, DarwinANSState, 1, NULL,
                               aux[5].size),
        VMSTATE_VBUFFER_UINT32(aux[6].store, DarwinANSState, 1, NULL,
                               aux[6].size),
        VMSTATE_VBUFFER_UINT32(aux[7].store, DarwinANSState, 1, NULL,
                               aux[7].size),
        VMSTATE_UINT64(cap, DarwinANSState),
        VMSTATE_UINT32(vs, DarwinANSState),
        VMSTATE_UINT32(cc, DarwinANSState),
        VMSTATE_UINT32(csts, DarwinANSState),
        VMSTATE_UINT32(aqa, DarwinANSState),
        VMSTATE_UINT32(intms, DarwinANSState),
        VMSTATE_UINT64(asq, DarwinANSState),
        VMSTATE_UINT64(acq, DarwinANSState),
        VMSTATE_UINT64(ioq_sq_base, DarwinANSState),
        VMSTATE_UINT64(ioq_cq_base, DarwinANSState),
        VMSTATE_UINT32(max_pend_cmds, DarwinANSState),
        VMSTATE_UINT32(linear_sq_ctrl, DarwinANSState),
        VMSTATE_UINT32(modesel, DarwinANSState),
        VMSTATE_UINT32(base_cmd_id, DarwinANSState),
        VMSTATE_BOOL(booted, DarwinANSState),
        VMSTATE_UINT32(num_tcbs, DarwinANSState),
        VMSTATE_UINT64(asq_tcb_base, DarwinANSState),
        VMSTATE_UINT64(iosq_tcb_base, DarwinANSState),
        VMSTATE_UINT32(acq_head, DarwinANSState),
        VMSTATE_UINT32(acq_tail, DarwinANSState),
        VMSTATE_BOOL(acq_phase, DarwinANSState),
        VMSTATE_UINT32(iocq_head, DarwinANSState),
        VMSTATE_UINT32(iocq_tail, DarwinANSState),
        VMSTATE_BOOL(iocq_phase, DarwinANSState),
        VMSTATE_UINT64(iosq_addr, DarwinANSState),
        VMSTATE_UINT64(iocq_addr, DarwinANSState),
        VMSTATE_UINT16(iosq_size, DarwinANSState),
        VMSTATE_UINT16(iocq_size, DarwinANSState),
        VMSTATE_UINT16(iocq_id, DarwinANSState),
        VMSTATE_UINT16(iosq_id, DarwinANSState),
        VMSTATE_BOOL(iosq_live, DarwinANSState),
        VMSTATE_BOOL(iocq_live, DarwinANSState),
        VMSTATE_BOOL(iocq_ien, DarwinANSState),
        VMSTATE_UINT64(n_admin, DarwinANSState),
        VMSTATE_UINT64(n_io, DarwinANSState),
        VMSTATE_UINT64(n_read_blocks, DarwinANSState),
        VMSTATE_UINT64(n_write_blocks, DarwinANSState),
        VMSTATE_UINT64(n_sart_denied, DarwinANSState),
        VMSTATE_END_OF_LIST()
    },
    .subsections = (const VMStateDescription * const []) {
        &vmstate_darwin_ans_sart_power,
        NULL
    },
};

static const Property darwin_ans_properties[] = {
    DEFINE_PROP_STRING("name", DarwinANSState, name),
    DEFINE_PROP_DRIVE("drive", DarwinANSState, blk),
    DEFINE_PROP_UINT32("nvmmu-size", DarwinANSState, nvmmu_size, 0),
    /* /arm-io/sart-ans "sart-power-reg-offset"; see sart_power_off. */
    DEFINE_PROP_UINT32("sart-power-reg-offset", DarwinANSState, sart_power_off, 0xffffffff),
    DEFINE_PROP_UINT32("nvme-size", DarwinANSState, nvme_size, 0),
    /* "nvme-queue-entries" from the device tree; 0x40 on t8140. */
    DEFINE_PROP_UINT32("queue-entries", DarwinANSState, queue_entries, 64),
    /* CAP.MQES. 0 means "the same as queue-entries", which is what the
     * guest requires on t8140; see the CAP comment in realize. */
    DEFINE_PROP_UINT32("mqes", DarwinANSState, mqes, 0),
    /* "nvme-num-sl": how many SL blocks reg[12] holds. */
    DEFINE_PROP_UINT32("num-sl", DarwinANSState, num_sl, 2),
    /* What SL_STATUS reads. 0x007f00ff satisfies both of SPTM's idle
     * tests; see ans_aux_read() for the derivation. */
    DEFINE_PROP_UINT32("sl-idle-status", DarwinANSState, sl_idle_status, 0x007f00ff),
    /* First entry of the node's "namespaces" triples. */
    DEFINE_PROP_UINT32("nsid", DarwinANSState, nsid, 1),
    /* Apple NAND is 4K-formatted; APFS's own block size is 4096 too. */
    DEFINE_PROP_UINT32("logical-block-size", DarwinANSState, lba_size, 4096),
    /* 64 per Linux/m1n1's struct nvme_command; see the header for why this is
     * a property and not a constant. */
    DEFINE_PROP_UINT32("sqe-stride", DarwinANSState, sqe_stride, 64),
    /*
     * MDTS: Identify Controller byte 0x4d, a max transfer of 2^n * CAP.MPSMIN
     * pages. With MPSMIN 0 (4K), 8 => 1 MiB.
     *
     * No source states Apple's real value, but the guest bounds it from below.
     * At 5 (128 KiB) the boot got as far as dyld opening the shared cache and
     * then died reading it (probe tag A9ROOT3):
     *
     *   libignition: dylib_cache: opened shared cache directory:
     *                             /System/Library/Caches/com.apple.dyld
     *   AppleNVMe Assert failed: ( PRPEntryCount <=
     *       ( ( fPRPSize / sizeof ( PRPEntry ) ) + 1 ) ) Exit
     *       @AppleNVMeRequest.cpp:901
     *   IOBlockStorageDriver: executeRequest: request failed to start!
     *   disk1: resource shortage.
     *   apfs_vnop_read:11932: disk1s1 ... retval 12 ... resid 262144 ...
     *   dyld[1]: dyld cache '(null)' not loaded
     *
     * i.e. APFS asked for 0x40000 (256 KiB) in one request; IONVMeFamily sizes
     * its per-request PRP list from MDTS (2^5 * 4K = 32 pages => 32 entries)
     * and refused to build the 64 entries that transfer needs, returning
     * ENOMEM up through IOBlockStorageDriver to APFS to dyld. So MDTS must
     * cover the largest request the block layer above will issue, and 256 KiB
     * is not the ceiling of that - 1 MiB is the first value with real headroom.
     *
     * The cost of being generous is bounded: ans_io() allocates one bounce
     * buffer of the transfer size per command, so 1 MiB * 64 tags worst case.
     * DARWIN_ANS_MDTS overrides it without a rebuild.
     */
    DEFINE_PROP_UINT32("mdts", DarwinANSState, mdts, 8),
    DEFINE_PROP_BOOL("secure-bar", DarwinANSState, secure_bar, true),
    DEFINE_PROP_BOOL("linear-sq", DarwinANSState, linear_sq, true),
    DEFINE_PROP_STRING("serial", DarwinANSState, serial),
    DEFINE_PROP_STRING("model", DarwinANSState, model),
};

static void darwin_ans_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    dc->realize = darwin_ans_realize;
    dc->vmsd = &vmstate_darwin_ans;
    dc->desc = "Apple ANS NVMe storage controller";
    device_class_set_props(dc, darwin_ans_properties);
    dc->user_creatable = false;
}

static const TypeInfo darwin_ans_info = {
    .name          = TYPE_DARWIN_ANS,
    .parent        = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(DarwinANSState),
    .class_init    = darwin_ans_class_init,
};

static void darwin_ans_register_types(void)
{
    type_register_static(&darwin_ans_info);
}

type_init(darwin_ans_register_types)

/* ---------------- RTKit personality ---------------- */

static void ans_rtkit_started(void *opaque)
{
    DarwinANSState *s = opaque;
    s->booted = true;
    ans_log(s, "coprocessor booted; BOOT_STATUS now reads 0x%08x\n", ANS_BOOT_STATUS_OK);
}

static bool ans_rtkit_handle(void *opaque, uint8_t ep, uint64_t msg)
{
    DarwinANSState *s = opaque;
    /*
     * m1n1's nvme_init() starts no endpoint beyond the shared system ones
     * (nvme.c:369-379, rtkit.c:22-27) -- but m1n1 is bare metal. XNU is not:
     * see ans_eps[] for why endpoint 0x20 has to exist. We advertise it,
     * RTBuddy starts it, and nothing has yet had to be said on it. Log and
     * never fault, so the first message that does arrive is visible.
     */
    ans_log(s, "AP -> ep 0x%02x msg 0x%016" PRIx64 " (no protocol above RTKit "
            "is modelled for ANS)\n", ep, msg);
    return true;
}

static void ans_rtkit_ep_start(void *opaque, uint8_t ep, uint32_t flag)
{
    DarwinANSState *s = opaque;
    /*
     * The "%sEndpoint%u" nub naming (kernelcache+0xb1f8ef) only applies to the
     * coprocessor's own endpoints, which start at 0x20; the shared system ones
     * (MGMT 0x00, CRASHLOG 0x01, SYSLOG 0x02, DEBUG 0x03, IOREPORT 0x04,
     * OSLOG 0x08) get their own RTBuddy nubs -- RTBuddyIOReportingEndpoint and
     * friends, visible in an io=0x1f log. Subtracting 0x1f from those underflows
     * and printed "ANS2Endpoint4294967273"; name them by index only when the
     * endpoint really is one of ours.
     */
    if (ep >= 0x20) {
        ans_log(s, "AP %s endpoint 0x%02x -> RTBuddy nub \"ANS2Endpoint%u\"\n",
                flag == 2 ? "started" : "stopped", ep, ep - 0x1f);
    } else {
        ans_log(s, "AP %s system endpoint 0x%02x\n",
                flag == 2 ? "started" : "stopped", ep);
    }
}

static const DarwinASCOps ans_asc_ops = {
    .started = ans_rtkit_started,
    .ep_start = ans_rtkit_ep_start,
    .handle = ans_rtkit_handle,
};

/*
 * The one endpoint the AP-side driver cannot do without.
 *
 * ans-nvme-references section 4 step 2 says "no ANS-specific RTKit endpoint
 * traffic is required", on the strength of m1n1's nvme_init() going straight
 * from rtkit_boot() to MMIO. That is true of m1n1 and false of XNU, and it is
 * why nothing ever touched a single NVMe register in our sandbox:
 *
 *   AppleANS2NVMeController::start(), IONVMeFamily+0xa9a4 (kext extracted from
 *   firmware/bootkc; addresses are the kext's own __TEXT_EXEC):
 *
 *       adrp x0, ... ; add x0, x0, #0x12c     ; "ANS2Endpoint1"
 *       mov  x1, #0
 *       bl   IOService::nameMatching
 *       cbz  x0, <REQUIRE line 364: "Could not create/find ANS2Endpoint1
 *                 matching dictionary">
 *       mov  x1, #-1                          ; timeout = forever
 *       bl   IOService::waitForMatchingService
 *       cbz  x0, <REQUIRE line 367: "ANS2Endpoint1 didn't show up">
 *
 * The timeout is -1, so the driver parks in that wait indefinitely and never
 * reaches the register mapping that follows it (lines 371..429, which map
 * device memory indices 4,5,6,7,8,9 into fAXI2AFDual / fANS2SLCommon /
 * fANS2CCUSecurityINT / fANS2ParityWidget / fANSSHABlock -- naming, at last,
 * the reg[] windows ans-nvme-references section 1 lists as "unresolved").
 * That is why no failure was ever logged either: it is not failing, it is
 * waiting.
 *
 * RTBuddy names each endpoint nub with the format string "%sEndpoint%u"
 * (kernelcache+0xb1f8ef) from the coprocessor's role and the endpoint index.
 * The index is `ep - 0x1f`, pinned by the DCP mapping this project already
 * established empirically: endpoint 0x20 is DCPEndpoint1 and endpoint 0x37 is
 * DCPEndpoint24 (0x37 - 0x20 == 24 - 1). So ANS2Endpoint1 is endpoint 0x20,
 * and advertising it in the RTKit endpoint map is all it takes.
 */
static const uint8_t ans_eps[] = { 0x20 };

/* ---------------- device tree glue ---------------- */

typedef struct {
    uint32_t phandle;
    DeviceState *found;
} ANSSartSearch;

static int ans_match_sart(Object *child, void *opaque)
{
    ANSSartSearch *q = opaque;
    if (q->found || !object_dynamic_cast(child, TYPE_DARWIN_SART)) {
        return 0;
    }
    q->found = DEVICE(child);
    return 0;
}

/* Resolve "iommu-parent" (a phandle) to the darwin-sart device that models it.
 * ANS points straight at /arm-io/sart-ans, not at a mapper child the way DART
 * users do, so this is a plain phandle lookup over /arm-io. */
static DeviceState *ans_find_sart(struct dtree_node *dt_root, struct dtree_node *ans)
{
    uint32_t *parent = adt_get_prop_val(ans, "iommu-parent");
    struct dtree_node *arm_io = adt_find_node(dt_root, "arm-io");
    if (!parent || !arm_io || adt_get_prop_len(ans, "iommu-parent") < 4) {
        return NULL;
    }
    const char *want = NULL;
    for (struct dtree_node *c = adt_first_child(arm_io); c;
         c = adt_next_sibling(arm_io, c)) {
        uint32_t *ph = adt_get_prop_val(c, "AAPL,phandle");
        if (ph && *ph == parent[0]) {
            want = adt_get_prop_val(c, "name");
            break;
        }
    }
    if (!want) {
        return NULL;
    }
    /* There is one SART on this SoC; if that ever stops being true, match on
     * the device's "name" property instead of taking the first. */
    ANSSartSearch q = { .phandle = parent[0] };
    object_child_foreach_recursive(object_get_root(), ans_match_sart, &q);
    if (q.found) {
        fprintf(stderr, "darwin-ans: DMA filtered by %s\n", want);
    }
    return q.found;
}

/*
 * Find the disk. In order:
 *   1. a blockdev/drive whose id is "ans"  (-drive if=none,id=ans,file=...)
 *   2. $DARWIN_ANS_DRIVE as a blockdev id
 *   3. the first unclaimed `-drive if=none` (bus 0, unit 0)
 * Doing this here rather than in darwin.c keeps all the block plumbing in one
 * file; the machine only has to call darwin_ans_create().
 */
/*
 * Scaffold helper, only used in DARWIN_ANS_SELFWIRE mode: find the generic
 * darwin-asc that darwin_ascs_create() built for /arm-io/ans (role "ANS2") and
 * disable its register window, so that the one darwin_ans_create() is about to
 * build -- the one that advertises endpoint 0x20 -- is the one the guest talks
 * to. Nothing has run in the guest yet at machine-init-done, so no state is
 * lost. Delete along with the rest of the scaffold.
 */
static int ans_retire_asc(Object *child, void *opaque)
{
    if (!object_dynamic_cast(child, TYPE_DARWIN_ASC)) {
        return 0;
    }
    DeviceState *dev = DEVICE(child);
    const char *role = darwin_asc_role(dev);
    if (!role || strcmp(role, "ANS2")) {
        return 0;
    }
    MemoryRegion *mr = sysbus_mmio_get_region(SYS_BUS_DEVICE(dev), 0);
    memory_region_set_enabled(mr, false);
    fprintf(stderr, "darwin-ans: DARWIN_ANS_SELFWIRE retired the generic "
            "darwin-asc for role ANS2\n");
    return 0;
}

static void ans_selfwire_retire_generic_asc(void)
{
    object_child_foreach_recursive(object_get_root(), ans_retire_asc, NULL);
}

static BlockBackend *ans_find_drive(void)
{
    const char *id = getenv("DARWIN_ANS_DRIVE");
    BlockBackend *blk = blk_by_name(id ? id : "ans");
    if (blk) {
        return blk;
    }
    DriveInfo *di = drive_get(IF_NONE, 0, 0);
    return di ? blk_by_legacy_dinfo(di) : NULL;
}

DeviceState *darwin_ans_create(struct dtree_node *dt_root, uint64_t iobase, DeviceState *aic)
{
    struct dtree_node *ans = adt_find_node(dt_root, "arm-io/ans");
    if (!ans || !adt_get_prop_val(ans, "compatible")) {
        return NULL;            /* dt_fixup was not run with -enable ans */
    }

    struct adt_io_reg *reg = adt_get_prop_val(ans, "reg");
    size_t nreg = reg ? adt_get_prop_len(ans, "reg") / sizeof(*reg) : 0;
    const char *name = adt_get_prop_val(ans, "name");
    uint32_t *irqs = adt_get_prop_val(ans, "interrupts");
    size_t n_irqs = irqs ? adt_get_prop_len(ans, "interrupts") / 4 : 0;
    uint32_t *qe = adt_get_prop_val(ans, "nvme-queue-entries");
    uint32_t *iidx = adt_get_prop_val(ans, "nvme-interrupt-idx");
    uint32_t *ns = adt_get_prop_val(ans, "namespaces");
    bool secure_bar = adt_get_prop_val(ans, "nvme-secure-bar") != NULL;
    bool linear_sq = adt_get_prop_val(ans, "nvme-linear-sq") != NULL;

    /*
     * Which reg index is which is a per-generation decision, and m1n1 makes it
     * on exactly this test (src/nvme.c:311-338): a node with "nvme-secure-bar"
     * is the M4+ family, NVMMU in reg[3] and NVMe in reg[9]; without it both
     * live in reg[3]. Our SPTM agrees (see the file header). We refuse to guess
     * for a node we have not seen.
     */
    if (nreg < 10 || !secure_bar) {
        fprintf(stderr, "darwin-ans: %s has %zu reg entries and %s nvme-secure-bar; "
                "only the reg[3]=NVMMU / reg[9]=NVMe layout is modelled, skipping\n",
                name ? name : "ans", nreg, secure_bar ? "does have" : "no");
        return NULL;
    }

    uint64_t nvmmu_base = reg[3].base + iobase;
    uint64_t nvme_base = reg[9].base + iobase;
    uint32_t nvmmu_size = reg[3].len;
    /*
     * reg[9] declares 0x10000, which is exactly what SPTM maps (4 pages of 16K,
     * sptm:0xfffffff0270bec84). We back more so that a driver reaching for
     * LINEAR_IOSQ_DB at +0x24910 through this window lands on us rather than on
     * darwin-unimp -- checked against every other /arm-io reg entry, nothing
     * else claims 0x1bdcc0000..0x1bdcf0000.
     */
    uint32_t nvme_size = MAX(reg[9].len, 0x30000);

    DeviceState *dev = qdev_new(TYPE_DARWIN_ANS);
    qdev_prop_set_string(dev, "name", name ? name : "ans");
    qdev_prop_set_uint32(dev, "nvmmu-size", nvmmu_size);
    qdev_prop_set_uint32(dev, "nvme-size", nvme_size);
    {
        struct dtree_node *sart_node = adt_find_node(dt_root, "arm-io/sart-ans");
        uint32_t *pwr = sart_node ? adt_get_prop_val(sart_node, "sart-power-reg-offset") : NULL;
        struct adt_io_reg *sreg = sart_node ? adt_get_prop_val(sart_node, "reg") : NULL;
        size_t n_sreg = sreg ? adt_get_prop_len(sart_node, "reg") / sizeof(*sreg) : 0;
        /* Only meaningful when sart-ans reg[2] really is our reg[3]. */
        if (pwr && n_sreg >= 3 && sreg[2].base == reg[3].base && *pwr + 4 <= nvmmu_size) {
            qdev_prop_set_uint32(dev, "sart-power-reg-offset", *pwr);
        }
    }
    if (qe && *qe) {
        qdev_prop_set_uint32(dev, "queue-entries", *qe);
    }
    if (ns && adt_get_prop_len(ans, "namespaces") >= 12) {
        /* triples of (index, nsid, size-ish); the first is (1, 1, 0) on t8140 */
        qdev_prop_set_uint32(dev, "nsid", ns[1]);
    }
    qdev_prop_set_bit(dev, "secure-bar", secure_bar);
    qdev_prop_set_bit(dev, "linear-sq", linear_sq);
    qdev_prop_set_string(dev, "serial", "DARWINVM0000000001");
    qdev_prop_set_string(dev, "model", "APPLE SSD (darwin-ans)");

    uint32_t *nsl = adt_get_prop_val(ans, "nvme-num-sl");
    qdev_prop_set_uint32(dev, "num-sl", nsl ? *nsl : 1);

    BlockBackend *blk = ans_find_drive();
    if (blk) {
        qdev_prop_set_drive_err(dev, "drive", blk, &error_fatal);
    }

    /*
     * The auxiliary windows, described before realize because a qdev property
     * per window would be six near-identical properties for no benefit; this
     * device is not user-creatable and darwin_ans_create() is its only caller.
     * The set is "every non-empty reg entry that is not one of the two we model
     * properly, and not reg[6]".
     *
     * reg[6] (0x17dd47c00 + 0x4000) is deliberately left to darwin-unimp: it
     * overlaps /arm-io/sart-ans reg[1] (0x17dd44000 + 0x4000) by 0x400 bytes,
     * darwin_sart.c already maps that window, and two priority-0 regions
     * fighting over 0x17dd47c00..0x17dd48000 would be decided by creation
     * order. Nothing has been observed touching it.
     */
    DarwinANSState *s = DARWIN_ANS(dev);
    static const unsigned aux_regs[] = { 1, 4, 5, 10, 11, 12 };
    for (size_t i = 0; i < ARRAY_SIZE(aux_regs) && s->n_aux < ANS_AUX_MAX; i++) {
        unsigned r = aux_regs[i];
        if (r >= nreg || !reg[r].len) {
            continue;
        }
        s->aux[s->n_aux].reg_index = r;
        s->aux[s->n_aux].size = reg[r].len;
        s->aux[s->n_aux].is_sl = (r == 12);
        s->n_aux++;
    }

    SysBusDevice *sbd = SYS_BUS_DEVICE(dev);
    sysbus_realize_and_unref(sbd, &error_fatal);
    sysbus_mmio_map(sbd, 0, nvmmu_base);
    sysbus_mmio_map(sbd, 1, nvme_base);
    for (unsigned i = 0; i < s->n_aux; i++) {
        sysbus_mmio_map(sbd, 2 + i, reg[s->aux[i].reg_index].base + iobase);
    }

    /*
     * "nvme-interrupt-idx" = 4 selects the 5th entry of "interrupts" (0x40f on
     * t8140): NVMe completions have their own AIC line, separate from the four
     * mailbox IRQs darwin_asc.c wires. Linux requests exactly one IRQ and polls
     * both completion queues from it (apple.c:707-723).
     */
    unsigned idx = iidx ? *iidx : 4;
    if (aic && idx < n_irqs) {
        sysbus_connect_irq(sbd, 0, darwin_aic_get_irq(aic, irqs[idx]));
    } else {
        fprintf(stderr, "darwin-ans: no interrupt at nvme-interrupt-idx %u "
                "(%zu interrupts); completions will not raise an IRQ\n", idx, n_irqs);
    }

    s->sart = ans_find_sart(dt_root, ans);

    fprintf(stderr, "darwin-ans: %s NVMMU at 0x%" PRIx64 "+0x%x, NVMe at 0x%" PRIx64
            "+0x%x (declared 0x%" PRIx64 "), %u tags, nsid %u, irq 0x%x, disk %s\n",
            name ? name : "ans", nvmmu_base, nvmmu_size, nvme_base, nvme_size,
            reg[9].len, s->queue_entries, s->nsid,
            (idx < n_irqs) ? irqs[idx] : 0,
            blk ? blk_name(blk) : "(none: pass -drive if=none,id=ans,file=...)");
    if (blk) {
        int64_t len = blk_getlength(blk);
        fprintf(stderr, "darwin-ans: namespace %u = %" PRId64 " bytes / %" PRId64
                " blocks of %u\n", s->nsid, len, len / s->lba_size, s->lba_size);
    }

    if (ans_selfwire()) {
        /* darwin_ascs_create() already made a generic mailbox for this node,
         * with no endpoint list. Take its MMIO window away before we map our
         * own on top. See the scaffold section below. */
        ans_selfwire_retire_generic_asc();
    }
    /* The RTKit half. One endpoint: see ans_eps[]. */
    return darwin_asc_create(ans, iobase, aic, ans_eps, ARRAY_SIZE(ans_eps),
                             &ans_asc_ops, s);
}

/* ---------------- bring-up scaffold: DARWIN_ANS_SELFWIRE ---------------- */

/*
 * darwin.c is orchestrator-owned, so until it calls darwin_ans_create() itself
 * there is no way to exercise this model at all. DARWIN_ANS_SELFWIRE=1 makes
 * the device create itself at machine-init-done instead:
 *
 *   - it re-reads the device tree from the machine's own "dtree" property (the
 *     same file darwin.c mapped; we only read reg / interrupts / booleans out
 *     of it, none of which anything patches at runtime),
 *   - it finds the AIC and the SART through QOM rather than being handed them,
 *   - and it does not create an ASC, because in this mode darwin_ascs_create()
 *     has already made the generic one for /arm-io/ans.
 *
 * Delete this whole section once darwin.c has:
 *
 *     #include "xnu/darwin_ans.h"
 *     ...
 *     darwin_ans_create(dt_root, iobase, aic);
 *     static const char *const claimed_ascs[] = { "dcp", "sep", "ans" };
 *
 * It is inert unless the environment variable is set.
 */
static int ans_match_aic(Object *child, void *opaque)
{
    DeviceState **out = opaque;
    if (!*out && object_dynamic_cast(child, TYPE_DARWIN_AIC)) {
        *out = DEVICE(child);
    }
    return 0;
}

static void ans_selfwire_done(Notifier *n, void *unused)
{
    g_autofree char *path = object_property_get_str(OBJECT(qdev_get_machine()),
                                                    "dtree", NULL);
    if (!path) {
        fprintf(stderr, "darwin-ans: DARWIN_ANS_SELFWIRE set but the machine has "
                "no \"dtree\" property\n");
        return;
    }
    char *buf = NULL;
    gsize len = 0;
    if (!g_file_get_contents(path, &buf, &len, NULL)) {
        fprintf(stderr, "darwin-ans: DARWIN_ANS_SELFWIRE could not re-read %s\n", path);
        return;
    }
    /* Deliberately not freed: the device keeps no pointers into it, but the
     * cost of a leak here is one device tree and the cost of getting it wrong
     * is a use-after-free in a bring-up path. */
    struct dtree_node *dt_root = (struct dtree_node *)buf;
    struct dtree_node *arm_io = adt_find_node(dt_root, "arm-io");
    uint64_t *ranges = arm_io ? adt_get_prop_val(arm_io, "ranges") : NULL;
    if (!ranges) {
        fprintf(stderr, "darwin-ans: DARWIN_ANS_SELFWIRE found no /arm-io ranges\n");
        return;
    }
    DeviceState *aic = NULL;
    object_child_foreach_recursive(object_get_root(), ans_match_aic, &aic);
    fprintf(stderr, "darwin-ans: DARWIN_ANS_SELFWIRE creating the NVMe half only "
            "(the generic darwin-asc already owns /arm-io/ans reg[0])\n");
    darwin_ans_create(dt_root, ranges[1] /* IO_RANGE_BASE_OFFSET */, aic);
}

static Notifier ans_selfwire_notifier = { .notify = ans_selfwire_done };

static void ans_selfwire_register(void)
{
    if (ans_selfwire()) {
        qemu_add_machine_init_done_notifier(&ans_selfwire_notifier);
    }
}

type_init(ans_selfwire_register)
