#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "qapi/error.h"
#include "hw/arm/boot.h"
#include "hw/arm/machines-qom.h"
#include "cpu.h"
#include "qom/object.h"
#include "system/address-spaces.h"
#include "system/reset.h"
#include "exec/memattrs.h"
#include "qemu/module.h"
#include "qemu/option.h"
#include "qemu/config-file.h"
#include "cpregs.h"
#include "hw/arm/exynos4210.h"
#include "system/system.h"
#include "hw/core/sysbus.h"
#include "hw/core/platform-bus.h"
#include "xnu/boot/xnuboot.h"
#include "xnu/apple_dtree.h"
#include "xnu/apple_regs.h"
#include "hw/arm/apple_amcc.h"
#include "xnu/patch.h"
#include "xnu/macho.h"
#include "xnu/darwin_fb.h"
#include "xnu/darwin_aic.h"
#include "xnu/darwin_dcp.h"
#include "xnu/darwin_asc.h"
#include "xnu/darwin_sart.h"
#include "xnu/darwin_dart.h"
#include "xnu/darwin_sep.h"
#include "xnu/darwin_ans.h"
#include "xnu/darwin_smc.h"
#include "xnu/darwin_unimp.h"
#include "xnu/darwin_smp.h"
#include "xnu/darwin_spmi.h"
#include "xnu/gxfstat.h"

// See device tree specification section 2.3.8: ranges
#define IO_RANGE_BASE_OFFSET     1

// Use this for AICs where we don't know how many interrupts there should be
#define A_GOOD_NUMBER_OF_IRQS    0x1000

#define EXPECTED_FIRMWARE_NAME   "qemu-sptm"

static char *g_default_args = (char*)"debug=0x8 kextlog=0xffff cpus=1 rd=md0 serial=7 -v -noprogress keepsyms=1 wdt=-1 -enable_kprintf_spam wlan-olyhal-abort";

#define CPACR_ENABLE_FPU         (( BIT(20) | BIT(21) ))
#define CPTR_ENABLE_FPU          (( BIT(20) | BIT(21) ))

#define TYPE_DARWIN_MACHINE MACHINE_TYPE_NAME("darwin")
OBJECT_DECLARE_SIMPLE_TYPE(DarwinState, DARWIN_MACHINE)

struct DarwinState {
    MachineState parent_obj;
    ARMCPU *cpu;
    ARMCPU *cpus[DARWIN_MAX_CPUS];
    struct xnu_boot_info bootinfo;
};

MACHINE_CLASS_ARG(bootkc);
MACHINE_CLASS_ARG(args);
MACHINE_CLASS_ARG(dtree);
MACHINE_CLASS_ARG(sptm);
MACHINE_CLASS_ARG(txm);
MACHINE_CLASS_ARG(tc);
MACHINE_CLASS_ARG(ramdisk);
MACHINE_CLASS_ARG(fb);
MACHINE_CLASS_ARG(fbmode);

static void alloc_zeroed(const char *name, hwaddr pa, size_t len) {
    if (0 == len) {
        fprintf(stderr, "error: alloc_ram called with len=0 for region %s\n", name);
        exit(1);
    }
    MemoryRegion *ram_main = get_system_memory();
    MemoryRegion *ram_subreg = g_new(MemoryRegion, 1);
    memory_region_init_ram(ram_subreg, NULL, name, len, &error_fatal);
    memory_region_add_subregion(ram_main, pa, ram_subreg);
    address_space_set(&address_space_memory, pa, 0, len, MEMTXATTRS_UNSPECIFIED);
}

static void do_darwin_reset(void *state) {
    DarwinState *s = DARWIN_MACHINE((MachineState *)state);
    ARMCPU *cpu = s->cpu;
    CPUState *cs = CPU(cpu);
    CPUARMState *env = &cpu->env;

    cpu_reset(cs);

    assert(2 == arm_highest_el(env));
    env->xregs[0] = s->bootinfo.init_x0;
    env->pc = s->bootinfo.init_pc;

    // SPTM needs fpu enabled:
    env->cp15.cpacr_el1 |= CPACR_ENABLE_FPU;
    env->cp15.cptr_el[2] |= CPTR_ENABLE_FPU;
    arm_rebuild_hflags(env);

    for (unsigned i = 1; i < s->parent_obj.smp.cpus; i++) {
        cpu_reset(CPU(s->cpus[i]));
    }
    if (s->parent_obj.smp.cpus > 1) {
        darwin_smp_reset();
    }
}

static mmap_file_t check_and_open(const char *path, const char *errmsg) {
    int fd;
    struct stat stats;
    void *mapping;

    if (!path) goto fail;

    fd = open(path, O_RDONLY | O_BINARY);
    if (fd < 0) goto fail;

    fstat(fd, &stats);
    mapping = mmap(NULL, stats.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (MAP_FAILED == mapping) goto fail;

    if (is_im4p(mapping)) {
        fprintf(stderr, "error: %s is an im4p, you need to unwrap it (eg. ipsw img4 im4p extract)\n", path);
        goto fail;
    }

    return (mmap_file_t){
        .buf = mapping,
        .len = stats.st_size,
    };

fail:
    fprintf(stderr, "%s\n", errmsg);
    exit(1);
}

static void init_cpu_impl(struct dtree_node *dt_root) {
    struct dtree_node *cpu0 = adt_find_node(dt_root, "cpus/cpu0");
    struct adt_io_reg *cpu_impl = adt_get_prop_val(cpu0, "cpu-impl-reg");
    struct adt_io_reg *cpm_impl = adt_get_prop_val(cpu0, "cpm-impl-reg");
    alloc_zeroed("cpu_reg_impl", cpu_impl[0].base, cpu_impl[0].len);
    alloc_zeroed("cpm_reg_impl", cpm_impl[0].base, cpm_impl[0].len);
}

static DeviceState *init_uart(struct dtree_node *dt_root, uint64_t iobase, DeviceState *aic) {
    struct dtree_node *uart = adt_find_node(dt_root, "arm-io/uart0");
    struct adt_io_reg *uart_reg = adt_get_prop_val(uart, "reg");
    // Deliberately left unconnected. XNU's Apple serial driver never clears
    // UINTP, and exynos4210_uart only deasserts its line when that is cleared,
    // so a connected line would latch high forever and storm the AIC. The
    // console works because XNU polls the UART; nothing depends on this
    // interrupt today.
    return exynos4210_uart_create(uart_reg[0].base + iobase, 16, 0, serial_hd(0), 0);
}

// -fb WxH[@scale] / -fbmode text|graphics
static void parse_fb_args(struct xnu_boot_info *info) {
    info->fb_width = info->fb_height = 0;
    info->fb_scale = 1;
    info->fb_graphics = false;

    if (!info->fb || !*info->fb || 0 == strcmp(info->fb, "off") || 0 == strcmp(info->fb, "none")) {
        return;
    }

    unsigned w = 0, h = 0, s = 1;
    int n = sscanf(info->fb, "%ux%u@%u", &w, &h, &s);
    if (n < 2 || !w || !h || w > 8192 || h > 8192 || s < 1 || s > 3) {
        fprintf(stderr, "error: bad -fb '%s', expected WxH[@scale] (eg. 828x1792@2)\n", info->fb);
        exit(1);
    }

    info->fb_width = w;
    info->fb_height = h;
    info->fb_scale = s;

    if (info->fbmode) {
        if (0 == strcmp(info->fbmode, "graphics")) {
            info->fb_graphics = true;
        } else if (0 != strcmp(info->fbmode, "text")) {
            fprintf(stderr, "error: bad -fbmode '%s', expected text or graphics\n", info->fbmode);
            exit(1);
        }
    }
}

static void init_sep(struct dtree_node *dt_root) {
    // This is a bare-bones sep InvalidateHmac config=1 implementation that ignores all register reads/ writes.
    // Since we fixup the device tree to have sio-hmac1-disable-mask = -1, InvalidateHmac is effectively disabled,
    // so long as we can read/ write the "registers" in the reg-block.
    struct dtree_node *sep = adt_find_node(dt_root, "arm-io/sep/iop-sep-nub/InvalidateHmac");
    if (!sep) return;
    struct adt_io_reg *sep_reg = adt_get_prop_val(sep, "reg-block");

    alloc_zeroed("sep", sep_reg[0].base, sep_reg[0].len);
}

// Real AIC model (see darwin_aic.c). Falls back to the old "zeroed RAM" stub
// with DARWIN_AIC_STUB=1 for debugging.
static DeviceState *init_aic(struct dtree_node *dt_root, uint64_t iobase, DeviceState *cpudev) {
    if (getenv("DARWIN_AIC_STUB")) {
        struct dtree_node *aic = adt_find_node(dt_root, "arm-io/aic");
        struct adt_io_reg *aic_reg = adt_get_prop_val(aic, "reg");
        uint64_t base = aic_reg[0].base + iobase;
        alloc_zeroed("aic", base, aic_reg[0].len);
        uint32_t num_irqs = A_GOOD_NUMBER_OF_IRQS;
        address_space_write(&address_space_memory, base + 0xC, MEMTXATTRS_UNSPECIFIED, &num_irqs, sizeof(num_irqs));
        return NULL;
    }
    // The CPU is not realized yet, so it has no canonical QOM path and a link
    // to its gpio would be silently stored as "". darwin_init connects the
    // output after qdev_realize instead.
    return darwin_aic_create(dt_root, iobase, NULL);
}

static void setup_mte(Object *cpuobj, MachineState *machine, struct xnu_boot_info *info) {
    MemoryRegion *tag_sysmem = NULL;

    if (!object_property_find(cpuobj, "tag-memory")) {
        fprintf(stderr, "cpu missing tag-memory property; MTE can't be enabled\n");
        exit(1);
    }

    tag_sysmem = g_new(MemoryRegion, 1);
    memory_region_init(tag_sysmem, OBJECT(machine), "tag-memory", UINT64_MAX / 32);
    object_property_set_link(cpuobj, "tag-memory", OBJECT(tag_sysmem), &error_abort);

    MemoryRegion *tagram = g_new(MemoryRegion, 1);
    memory_region_init_ram(tagram, NULL, "mte_tags", info->dram_size / 32, &error_fatal);
    memory_region_add_subregion(tag_sysmem, info->dram_base / 32, tagram);
}

__attribute__((unused))
static int get_soc_gen(struct dtree_node *dt_root) {
    struct dtree_node *arm_io = adt_find_node(dt_root, "arm-io");
    assert(arm_io);
    const char *soc_gen_str = adt_get_prop_val(arm_io, "soc-generation");
    if (!soc_gen_str || 'H' != soc_gen_str[0]) return 0;
    int soc_gen = 0;
    sscanf(soc_gen_str, "H%d", &soc_gen);
    return soc_gen;
}

static void check_dtree(struct dtree_node *dt_root) {
    struct dtree_node *chosen = adt_find_node(dt_root, "chosen");
    assert(chosen);

    const char *fw_vers = adt_get_prop_val(chosen, "firmware-version");
    assert(fw_vers);

    if (0 != strcmp(fw_vers, EXPECTED_FIRMWARE_NAME)) {
        fprintf(stderr, "error: device tree firmware-version doesn't match %s, did you run dt_fixup on this device tree?\n", EXPECTED_FIRMWARE_NAME);
        exit(1);
    }
}

static void darwin_init(MachineState *ms) {
    DarwinState *s = DARWIN_MACHINE(ms);
    struct xnu_boot_info *info = &s->bootinfo;
    struct dtree_node *dt_root;

    if (!info->args) info->args = g_default_args;
    parse_fb_args(info);
    info->bootkc_f = check_and_open(info->bootkc, "error opening XNU kernel");
    info->dtree_f = check_and_open(info->dtree, "error opening device tree");
    info->tc_f = check_and_open(info->tc, "error opening trust cache");
    info->ramdisk_f = check_and_open(info->ramdisk, "error opening ramdisk");
    if (info->sptm) {
        info->sptm_f = check_and_open(info->sptm, "error opening SPTM");
        info->txm_f = check_and_open(info->txm, "error opening TXM");
    }
    dt_root = info->dtree_f.buf;

    check_dtree(dt_root);

    struct dtree_node *cpu_nodes = adt_find_node(dt_root, "cpus");
    if (!cpu_nodes || ms->smp.cpus > cpu_nodes->nChildren) {
        error_report("darwin: requested CPUs exceed the device tree CPU count");
        exit(1);
    }
    if (ms->smp.cpus > 1) {
        struct dtree_node *n = adt_first_child(cpu_nodes);
        if (n != adt_find_node(dt_root, "cpus/cpu0")) {
            error_report("darwin: SMP requires cpu0 first in the device tree");
            exit(1);
        }
        for (unsigned i = 0; i < ms->smp.cpus; i++) {
            uint32_t *affinity = adt_get_prop_val(n, "reg");
            if (!affinity || adt_get_prop_len(n, "reg") != sizeof(*affinity) ||
                (i == 0 && *affinity != 0)) {
                error_report("darwin: unsupported SMP CPU affinity layout");
                exit(1);
            }
            n = adt_next_sibling(cpu_nodes, n);
        }
        /* XNU's ml_parse_cpu_topology uses cpus=N to bound the EDT list. */
        g_auto(GStrv) words = g_strsplit_set(info->args, " \t", -1);
        g_autofree char *expected = g_strdup_printf("cpus=%u", ms->smp.cpus);
        GString *args = g_string_new(expected);
        for (unsigned i = 0; words[i]; i++) {
            if (g_str_has_prefix(words[i], "cpumask=")) {
                error_report("darwin: SMP does not support cpumask; use -smp N");
                exit(1);
            }
            if (g_str_has_prefix(words[i], "cpus=")) {
                if (info->args != g_default_args && strcmp(words[i], expected)) {
                    error_report("darwin: boot argument %s conflicts with -smp %u",
                                 words[i], ms->smp.cpus);
                    exit(1);
                }
                continue;
            }
            if (*words[i]) {
                g_string_append_c(args, ' ');
                g_string_append(args, words[i]);
            }
        }
        info->args = g_string_free(args, false);
        /* The historical counters and histogram are single-vCPU scaffolding. */
        gxfstat_enabled = false;
        warn_report("darwin: experimental SMP; %s", getenv("DARWIN_SMP_PV") ?
                    "virtual CPU power management enabled; suspend/hotplug unsupported" :
                    "XNU secondary startup requires the virtual platform adapter");
    }

    info->has_mte = kc_uses_mte(info->bootkc_f.buf);

    Object *cpuobj = object_new(ms->cpu_type);
    DeviceState *cpudev = DEVICE(cpuobj);
    ARMCPU *cpu = ARM_CPU(cpuobj);

    cpu->has_el2 = true;
    cpu->has_el3 = false;

    // Disable CBAR because some MSRs conflict with Apple Si specific ones (see aarch64_a57_initfn)
    unset_feature(&cpu->env, ARM_FEATURE_CBAR);
    unset_feature(&cpu->env, ARM_FEATURE_CBAR_RO);
    unset_feature(&cpu->env, ARM_FEATURE_EL3);
    unset_feature(&cpu->env, ARM_FEATURE_PMU);

    // SPTM requires EL2, and non-SPTM XNU can run in either EL1 or EL2, so just always use EL2
    set_feature(&cpu->env, ARM_FEATURE_EL2);

    struct dtree_node *cpu_node = adt_find_node(dt_root, "cpus/cpu0");
    u32 dtree_frq = *(u32*)adt_get_prop_val(cpu_node, "clock-frequency");
    cpu->gt_cntfrq_hz = dtree_frq;

    struct dtree_node *chosen_node = adt_find_node(dt_root, "chosen");
    info->dram_base = *(u64*)adt_get_prop_val(chosen_node, "dram-base");
    info->dram_size = *(u64*)adt_get_prop_val(chosen_node, "dram-size");

    s->cpu = ARM_CPU(cpuobj);
    s->cpus[0] = s->cpu;
    if (ms->smp.cpus > 1) {
        cpu->mp_affinity = *(uint32_t *)adt_get_prop_val(cpu_node, "reg");
        cpu->core_count = ms->smp.cpus;
    }
    arm_load_xnu(s->cpu, ms, info);
    if (info->has_mte) setup_mte(cpuobj, MACHINE(s), info);

    struct dtree_node *amcc_node = adt_find_node(dt_root, "chosen/lock-regs/amcc");
    AMCCState *amcc_dev = NULL;
    if (amcc_node) {
        amcc_dev = (AMCCState*)amcc_create(amcc_node);
    }
    apple_regs_init(cpu, amcc_dev, dt_root, info);

    struct dtree_node *next_cpu = adt_next_sibling(cpu_nodes, cpu_node);
    for (unsigned i = 1; i < ms->smp.cpus; i++) {
        ARMCPU *other = ARM_CPU(object_new(ms->cpu_type));
        s->cpus[i] = other;
        other->has_el2 = true;
        other->has_el3 = false;
        unset_feature(&other->env, ARM_FEATURE_CBAR);
        unset_feature(&other->env, ARM_FEATURE_CBAR_RO);
        unset_feature(&other->env, ARM_FEATURE_EL3);
        unset_feature(&other->env, ARM_FEATURE_PMU);
        set_feature(&other->env, ARM_FEATURE_EL2);
        other->gt_cntfrq_hz = dtree_frq;
        other->mp_affinity = *(uint32_t *)adt_get_prop_val(next_cpu, "reg");
        other->core_count = ms->smp.cpus;
        CPU(other)->start_powered_off = true;
        if (info->has_mte) {
            Object *tags = object_property_get_link(cpuobj, "tag-memory", &error_abort);
            object_property_set_link(OBJECT(other), "tag-memory", tags, &error_abort);
        }
        apple_regs_init(other, NULL, dt_root, info);
        next_cpu = adt_next_sibling(cpu_nodes, next_cpu);
    }
    if (ms->smp.cpus > 1) {
        for (unsigned i = 0; i < ms->smp.cpus; i++) {
            darwin_smp_register_cpu(s->cpus[i]);
        }
    }

    struct dtree_node *arm_io = adt_find_node(dt_root, "arm-io");
    uint64_t *arm_io_ranges = adt_get_prop_val(arm_io, "ranges");
    uint64_t iobase = arm_io_ranges[IO_RANGE_BASE_OFFSET];
    assert(0 == arm_io_ranges[0]); // child bus phys addr must be zero

    if (!getenv("DARWIN_NO_UNIMP")) darwin_unimp_init(dt_root, iobase);
    DeviceState *aic = init_aic(dt_root, iobase, cpudev);
    DeviceState *uart = init_uart(dt_root, iobase, aic);
    darwin_darts_create(dt_root, iobase, aic);
    darwin_sarts_create(dt_root, iobase, aic);
    darwin_dcp_create(dt_root, iobase, aic);
    // The SEP is an ASC wrapper too, but speaks its own protocol above the
    // mailbox rather than RTKit, so it gets its own model (darwin_sep.c).
    darwin_sep_create(dt_root, iobase, aic);
    // The SMC is an ASC wrapper too, with its key protocol modelled in
    // darwin_smc.c; it claims "smc" below so the generic pass skips it.
    darwin_smc_create(dt_root, iobase, aic);
    // Any other coprocessor left enabled in the device tree gets a bare
    // RTKit mailbox, so XNU's RTBuddy can attach and start it.
    // The ANS storage coprocessor owns its own /arm-io/ans mailbox as well as
    // the NVMe and NVMMU register banks, so it is created before the generic
    // pass and claims "ans" below. It returns NULL harmlessly when dt_fixup
    // was not run with -enable ans, and runs without a backing store when no
    // -drive if=none,id=ans,file=... was given.
    //
    // DARWIN_ANS_SELFWIRE is darwin_ans.c's own bring-up scaffold: it creates
    // the NVMe half at machine-init-done and expects the generic ASC to
    // already exist, so in that mode we create nothing and leave "ans"
    // unclaimed. Delete this branch, and the scaffold, once the guarded path
    // has been boot-tested. ("ans" must stay last in the array for this.)
    static const char *const claimed_ascs[] = { "dcp", "sep", "smc", "ans" };
    unsigned n_claimed = ARRAY_SIZE(claimed_ascs);
    if (getenv("DARWIN_ANS_SELFWIRE")) {
        n_claimed--;
    } else {
        darwin_ans_create(dt_root, iobase, aic);
    }
    darwin_ascs_create(dt_root, iobase, aic, claimed_ascs, n_claimed);
    // SPMI controller + Dialog PMU (RTC). Created only when dt_fixup ran with
    // -enable spmi; the PMU's IRQ goes into the controller, the controller's
    // into the AIC. See darwin_spmi.c / darwin_pmu.c for the traced layout.
    darwin_spmi_create(dt_root, iobase, aic);
    init_sep(dt_root);
    if (ms->smp.cpus == 1) {
        init_cpu_impl(dt_root);
    } else {
        darwin_smp_init(s->cpus, ms->smp.cpus, dt_root, info);
    }

    // M4 (T8132) asserts SME's max VQ len is this many.
    // Specifically, rdsvl   x8, #0x1 must return 0x40.
    for (unsigned i = 0; i < ms->smp.cpus; i++) {
        ARMCPU *c = s->cpus[i];
        c->sme_vq.supported = 0x0b;
        qdev_realize(DEVICE(c), NULL, &error_fatal);
        if (ms->smp.cpus > 1) {
            darwin_smp_connect_cpu(c);
        } else {
            qdev_connect_gpio_out(DEVICE(c), GTIMER_HYPVIRT,
                                 qdev_get_gpio_in(DEVICE(c), ARM_CPU_FIQ));
        }
    }

    // Must come after realize, for the same reason as the FIQ above: before it,
    // the CPU has no canonical QOM path, object_property_set_link stores "" and
    // qemu_set_irq on the result is a silent no-op. That is why no AIC
    // interrupt was ever delivered to the guest.
    if (aic) {
        sysbus_connect_irq(SYS_BUS_DEVICE(aic), 0, qdev_get_gpio_in(cpudev, ARM_CPU_IRQ));
    }

    // Boot framebuffer display + keyboard bridge into the serial console
    darwin_fb_init(info, uart);

    qemu_register_reset(do_darwin_reset, s);
    munmap(info->bootkc_f.buf, info->bootkc_f.len);
    munmap(info->dtree_f.buf, info->dtree_f.len);
    munmap(info->tc_f.buf, info->tc_f.len);
    munmap(info->ramdisk_f.buf, info->ramdisk_f.len);
    if (info->sptm) {
        munmap(info->sptm_f.buf, info->sptm_f.len);
        munmap(info->txm_f.buf, info->txm_f.len);
    }
}

static void darwin_machine_init(MachineClass *mc) {
    mc->desc = "Generic Apple Silicon Device";
    mc->init = darwin_init;
    mc->max_cpus = DARWIN_MAX_CPUS;
    mc->default_cpus = 1;
    mc->default_cpu_type = ARM_CPU_TYPE_NAME("max");
}

static void darwin_machine_class_init(ObjectClass *oc, const void *data) {
    MachineClass *mc = MACHINE_CLASS(oc);

    object_class_property_add_str(oc, "bootkc", bootkc_darwin_class_get, bootkc_darwin_class_set);
    object_class_property_add_str(oc, "args", args_darwin_class_get, args_darwin_class_set);
    object_class_property_add_str(oc, "dtree", dtree_darwin_class_get, dtree_darwin_class_set);
    object_class_property_add_str(oc, "sptm", sptm_darwin_class_get, sptm_darwin_class_set);
    object_class_property_add_str(oc, "txm", txm_darwin_class_get, txm_darwin_class_set);
    object_class_property_add_str(oc, "tc", tc_darwin_class_get, tc_darwin_class_set);
    object_class_property_add_str(oc, "ramdisk", ramdisk_darwin_class_get, ramdisk_darwin_class_set);
    object_class_property_add_str(oc, "fb", fb_darwin_class_get, fb_darwin_class_set);
    object_class_property_add_str(oc, "fbmode", fbmode_darwin_class_get, fbmode_darwin_class_set);

    darwin_machine_init(mc);
}

static const TypeInfo darwin_machine_typeinfo = {
    .name           =  TYPE_DARWIN_MACHINE,
    .parent         =  TYPE_MACHINE,
    .class_init     =  darwin_machine_class_init,
    .instance_size  =  sizeof(DarwinState),
    .abstract       =  false,
    .interfaces     =  arm_machine_interfaces,
};

static void darwin_register_types(void) {
    type_register_static(&darwin_machine_typeinfo);
}

type_init(darwin_register_types)
