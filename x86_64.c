#include "nvmm.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <asm/bootparam.h>

/* 32MB - Above 16MB decompressor target */
#define KERN_ADDR		0x2000000
#define BOOT_ADDR		0x10000
#define CMDLINE_ADDR		0x20000
#define GDT_ADDR		0x1000
#define PML4_ADDR		0x2000
#define PDP_ADDR		0x3000
#define PD_ADDR			0x4000

#define X86_PAGE_SIZE		4096
#define SECTOR_SIZE		512

#define COM1_PORT		0x3f8
#define COM1_LSR_PORT		0x3fd
#define COM1_LSR_TX_EMPTY	0x60

#define E820_RAM		1
#define E820_RESERVED		2

#define GDT_CODE64_ENT		0x00af9b000000ffffULL
#define GDT_DATA64_ENT		0x00cf93000000ffffULL
#define GDT_LIMIT		23

#define BOOT_CS			0x8
#define BOOT_DS			0x10

#define CR0_DEFAULT		0x80050033
#define CR4_DEFAULT		0x620
#define EFER_DEFAULT		0xd01

#define PDE64_FLAGS		0xe3 /* Present, R/W, Accessed, Dirty, 2MB Hugepage */
#define PDE64_PAGE_SIZE		0x200000
#define PAGE_PRESENT_RW		0x63 /* Present, R/W, Accessed, Dirty */

/* Boot Protocol Constants */
#define SETUP_SECTS_DEFAULT	4
#define BOOT_LOADER_TYPE_NVMM	0xff
#define LOADFLAGS_LOADED_HIGH	0x01
#define X86_SUBARCH_CE4100	4
#define E820_MAX_ENTRIES	4
#define MMIO_HOLE_START		0xc0000000ULL
#define MMIO_HOLE_SIZE		0x40000000ULL
#define FOUR_GB			0x100000000ULL
#define COM1_IRQ		4
#define COM1_REG_COUNT		8
#define ASCII_PRINTABLE_MIN	32
#define ASCII_PRINTABLE_MAX	126

#define KVM_TSS_ADDR_VAL	0xfffbd000
#define KVM_IDMAP_ADDR_VAL	0xfffbc000

#define EBDA_START		0x9f000
#define EBDA_SIZE		0x1000
#define HIGH_RAM_START		0x100000

#define SEG_TYPE_CODE64		11
#define SEG_TYPE_DATA		3

#define KERNEL_ENTRY_OFFSET	0x200
#define X86_RFLAGS_DEFAULT	0x2

#define UART_RX_REG		0
#define UART_TX_REG		0
#define UART_IER_REG		1
#define UART_IIR_REG		2
#define UART_LCR_REG		3
#define UART_MCR_REG		4
#define UART_LSR_REG		5
#define UART_MSR_REG		6
#define UART_SCR_REG		7

#define UART_LCR_DLAB		0x80
#define UART_LSR_DR		0x01
#define UART_MSR_DEFAULT	0xb0

#define UART_IER_RDI		0x01
#define UART_IER_THRE		0x02
#define UART_IIR_NO_INT		0x01
#define UART_IIR_THRE		0x02
#define UART_IIR_RDI		0x04

static uint8_t com1_regs[COM1_REG_COUNT];
static int com1_thre_int_pending = 0;
static struct kvm_cpuid2 *cached_cpuid = NULL;

struct mpf_intel {
	char signature[4];
	uint32_t physptr;
	uint8_t length;
	uint8_t specification;
	uint8_t checksum;
	uint8_t feature1;
	uint8_t feature2;
	uint8_t feature3;
	uint8_t feature4;
	uint8_t feature5;
} __attribute__((packed));

struct mpc_table {
	char signature[4];
	uint16_t length;
	uint8_t spec;
	uint8_t checksum;
	char oem[8];
	char productid[12];
	uint32_t oemptr;
	uint16_t oemsize;
	uint16_t oemcount;
	uint32_t lapic;
	uint32_t reserved;
} __attribute__((packed));

struct mpc_cpu {
	uint8_t type;
	uint8_t apicid;
	uint8_t apicver;
	uint8_t cpuflag;
	uint32_t cpufeature;
	uint32_t featureflag;
	uint32_t reserved[2];
} __attribute__((packed));

struct mpc_bus {
	uint8_t type;
	uint8_t busid;
	char bustype[6];
} __attribute__((packed));

struct mpc_ioapic {
	uint8_t type;
	uint8_t apicid;
	uint8_t apicver;
	uint8_t flags;
	uint32_t apicaddr;
} __attribute__((packed));

struct mpc_intsrc {
	uint8_t type;
	uint8_t irqtype;
	uint16_t irqflag;
	uint8_t srcbus;
	uint8_t srcbusirq;
	uint8_t dstapic;
	uint8_t dstirq;
} __attribute__((packed));

struct mpc_lintsrc {
	uint8_t type;
	uint8_t irqtype;
	uint16_t irqflag;
	uint8_t srcbusid;
	uint8_t srcbusirq;
	uint8_t destapic;
	uint8_t destapiclint;
} __attribute__((packed));

static uint8_t mp_checksum(const void *p, size_t len)
{
	const uint8_t *bytes = (const uint8_t *)p;
	uint8_t sum = 0;
	size_t i;

	for (i = 0; i < len; i++)
		sum += bytes[i];
	return (uint8_t)(0 - sum);
}

static void setup_mptable(struct kvm_ctx *ctx, int nvcpu)
{
	uint8_t *ebda = (uint8_t *)ctx->mem + EBDA_START;
	struct mpc_table *mpc;
	struct mpf_intel *mpf;
	uint8_t *p;
	int i;
	uint8_t ioapic_id = (uint8_t)(nvcpu > 0 ? nvcpu : 1);

	memset(ebda, 0, EBDA_SIZE);

	mpc = (struct mpc_table *)ebda;
	memcpy(mpc->signature, "PCMP", 4);
	mpc->spec = 4;
	mpc->lapic = 0xfee00000;
	memcpy(mpc->oem, "ORPHANVM", 8);
	memcpy(mpc->productid, "NANOVMM     ", 12);

	p = (uint8_t *)(mpc + 1);

	for (i = 0; i < nvcpu; i++) {
		struct mpc_cpu *cpu = (struct mpc_cpu *)p;
		cpu->type = 0;
		cpu->apicid = (uint8_t)i;
		cpu->apicver = 0x14;
		cpu->cpuflag = 1 | (i == 0 ? 2 : 0);
		cpu->cpufeature = 0x600;
		cpu->featureflag = 0x1fbff;
		p += sizeof(struct mpc_cpu);
	}

	struct mpc_bus *bus = (struct mpc_bus *)p;
	bus->type = 1;
	bus->busid = 0;
	memcpy(bus->bustype, "ISA   ", 6);
	p += sizeof(struct mpc_bus);

	struct mpc_ioapic *ioapic = (struct mpc_ioapic *)p;
	ioapic->type = 2;
	ioapic->apicid = ioapic_id;
	ioapic->apicver = 0x11;
	ioapic->flags = 1;
	ioapic->apicaddr = 0xfec00000;
	p += sizeof(struct mpc_ioapic);

	for (i = 0; i < 16; i++) {
		struct mpc_intsrc *intsrc = (struct mpc_intsrc *)p;
		intsrc->type = 3;
		intsrc->irqtype = 0;
		intsrc->irqflag = 0;
		intsrc->srcbus = 0;
		intsrc->srcbusirq = (uint8_t)i;
		intsrc->dstapic = ioapic_id;
		intsrc->dstirq = (i == 0) ? 2 : (uint8_t)i;
		p += sizeof(struct mpc_intsrc);
	}

	struct mpc_intsrc *extint = (struct mpc_intsrc *)p;
	extint->type = 3;
	extint->irqtype = 3;
	extint->irqflag = 0;
	extint->srcbus = 0;
	extint->srcbusirq = 0;
	extint->dstapic = ioapic_id;
	extint->dstirq = 0;
	p += sizeof(struct mpc_intsrc);

	struct mpc_lintsrc *lint0 = (struct mpc_lintsrc *)p;
	lint0->type = 4;
	lint0->irqtype = 3;
	lint0->irqflag = 0;
	lint0->srcbusid = 0;
	lint0->srcbusirq = 0;
	lint0->destapic = 0xff;
	lint0->destapiclint = 0;
	p += sizeof(struct mpc_lintsrc);

	struct mpc_lintsrc *lint1 = (struct mpc_lintsrc *)p;
	lint1->type = 4;
	lint1->irqtype = 1;
	lint1->irqflag = 0;
	lint1->srcbusid = 0;
	lint1->srcbusirq = 0;
	lint1->destapic = 0xff;
	lint1->destapiclint = 1;
	p += sizeof(struct mpc_lintsrc);

	size_t mpc_len = (size_t)(p - ebda);
	mpc->length = (uint16_t)mpc_len;
	mpc->checksum = 0;
	mpc->checksum = mp_checksum(mpc, mpc_len);

	/* Set BDA EBDA segment pointer at 0x40E (0x9f000 >> 4 = 0x9f00) */
	*(uint16_t *)((uint8_t *)ctx->mem + 0x40E) = (uint16_t)(EBDA_START >> 4);

	/* MP Floating Pointer Structure at 0x9fc00 */
	mpf = (struct mpf_intel *)((uint8_t *)ctx->mem + 0x9fc00);
	memset(mpf, 0, sizeof(*mpf));
	memcpy(mpf->signature, "_MP_", 4);
	mpf->physptr = (uint32_t)EBDA_START;
	mpf->length = 1;
	mpf->specification = 4;
	mpf->checksum = mp_checksum(mpf, sizeof(struct mpf_intel));

	/* Also place a copy at physical address 0x0 (bottom 1K scan) */
	struct mpf_intel *mpf0 = (struct mpf_intel *)((uint8_t *)ctx->mem + 0x0);
	memcpy(mpf0, mpf, sizeof(*mpf));

	/* Also place a copy at 0xf0000 (64K BIOS scan) */
	struct mpf_intel *mpf_f = (struct mpf_intel *)((uint8_t *)ctx->mem + 0xf0000);
	memcpy(mpf_f, mpf, sizeof(*mpf));
}

/**
 * vm_arch_init() - Initialize x86_64 VM memory map, E820 table, and kernel.
 * @opts: Pointer to VMM configuration options.
 * @ctx: Pointer to KVM VM context.
 *
 * Configures the in-kernel PIC/PIT interrupt controllers, loads the bzImage
 * kernel and initramfs into memory, formats the boot command line, and
 * initializes E820 memory map entries with a reserved MMIO hole.
 */
void vm_arch_init(struct vmm_opts *opts, struct kvm_ctx *ctx)
{
	struct boot_params *bp;
	uint32_t setup_sects;
	uint64_t map_addr;
	long page_size;
	int kfd;
	struct stat kstat;

	page_size = sysconf(_SC_PAGESIZE);

	if (ioctl(ctx->vm_fd, KVM_SET_TSS_ADDR, KVM_TSS_ADDR_VAL) < 0)
		die("KVM_SET_TSS_ADDR");

	map_addr = KVM_IDMAP_ADDR_VAL;
	if (ioctl(ctx->vm_fd, KVM_SET_IDENTITY_MAP_ADDR, &map_addr) < 0)
		die("KVM_SET_IDENTITY_MAP_ADDR");
	if (ioctl(ctx->vm_fd, KVM_CREATE_IRQCHIP, 0) < 0)
		die("KVM_CREATE_IRQCHIP");

	struct kvm_pit_config pit_config = { .flags = 0 };

	if (ioctl(ctx->vm_fd, KVM_CREATE_PIT2, &pit_config) < 0)
		die("KVM_CREATE_PIT2");

	size_t ram_size = (opts->mem_size > MMIO_HOLE_START) ?
			  MMIO_HOLE_START : opts->mem_size;

	set_user_mem_region(ctx->vm_fd, 0, 0, ram_size, ctx->mem,
			    ctx->ram_fd, 0);
	printf("[NVMM_MEM] slot=0 gpa=0x0 hva=0x%llx size=0x%llx\n",
	       (unsigned long long)(uintptr_t)ctx->mem,
	       (unsigned long long)ram_size);

	if (opts->mem_size > MMIO_HOLE_START) {
		set_user_mem_region(ctx->vm_fd, 1, FOUR_GB,
				    opts->mem_size - MMIO_HOLE_START,
				    (char *)ctx->mem + MMIO_HOLE_START,
				    ctx->ram_fd, MMIO_HOLE_START);
		printf("[NVMM_MEM] slot=1 gpa=0x%llx hva=0x%llx size=0x%llx\n",
		       (unsigned long long)FOUR_GB,
		       (unsigned long long)(uintptr_t)((char *)ctx->mem + MMIO_HOLE_START),
		       (unsigned long long)(opts->mem_size - MMIO_HOLE_START));
	}
	fflush(stdout);

	if (!cached_cpuid) {
		int nent = 256;
		size_t sz = sizeof(*cached_cpuid) + nent * sizeof(struct kvm_cpuid_entry2);

		cached_cpuid = calloc(1, sz);
		if (!cached_cpuid)
			die("calloc cpuid");

		cached_cpuid->nent = nent;
		if (ioctl(ctx->kvm_fd, KVM_GET_SUPPORTED_CPUID, cached_cpuid) < 0)
			die("KVM_GET_SUPPORTED_CPUID");
	}

	if (opts->is_resume || !opts->kernel_path)
		return;

	kfd = open(opts->kernel_path, O_RDONLY);
	if (kfd < 0)
		die("open kernel");
	if (fstat(kfd, &kstat) < 0)
		die("fstat kernel");

	bp = (struct boot_params *)((uint8_t *)ctx->mem + BOOT_ADDR);
	memset(bp, 0, page_size);
	
	lseek(kfd, offsetof(struct boot_params, hdr), SEEK_SET);
	if (full_read(kfd, &bp->hdr, sizeof(struct setup_header)) !=
	    sizeof(struct setup_header))
		die("read setup_header");
	
	if (bp->hdr.setup_sects)
		setup_sects = bp->hdr.setup_sects;
	else
		setup_sects = 4;
	
	lseek(kfd, 0, SEEK_SET);
	if (full_read(kfd, bp, page_size) < 0)
		die("read boot_params");

	size_t payload_off = (setup_sects + 1) * SECTOR_SIZE;
	size_t payload_sz = (kstat.st_size > (off_t)payload_off) ?
			    (size_t)(kstat.st_size - payload_off) : 0;
	if (payload_sz == 0 || payload_sz > opts->mem_size - KERN_ADDR)
		die("invalid kernel payload size");

	lseek(kfd, payload_off, SEEK_SET);
	if (full_read(kfd, (uint8_t *)ctx->mem + KERN_ADDR, payload_sz) !=
	    (ssize_t)payload_sz)
		die("read kernel payload");
	close(kfd);

	if (opts->initrd_path) {
		struct stat istat;
		if (stat(opts->initrd_path, &istat) < 0)
			die("stat initrd");

		size_t initrd_sz = (size_t)istat.st_size;
		uint64_t initrd_max = opts->mem_size;
		if (initrd_max > MMIO_HOLE_START)
			initrd_max = MMIO_HOLE_START;
		if (bp->hdr.initrd_addr_max && initrd_max > bp->hdr.initrd_addr_max)
			initrd_max = bp->hdr.initrd_addr_max;

		if (initrd_sz > initrd_max)
			die("initrd larger than available guest memory");

		uint64_t initrd_addr = (initrd_max - initrd_sz) & ~0xfffULL;
		if (initrd_addr < KERN_ADDR + payload_sz)
			die("guest memory too small to fit kernel and initrd");

		size_t max_initrd = (size_t)(opts->mem_size - initrd_addr);
		ssize_t sz = load_file_into_mem(opts->initrd_path,
						(uint8_t *)ctx->mem + initrd_addr,
						max_initrd);
		if (sz < 0)
			die("load initrd payload");

		bp->hdr.ramdisk_image = (uint32_t)initrd_addr;
		bp->hdr.ramdisk_size = (uint32_t)sz;
	}

	bp->hdr.type_of_loader = BOOT_LOADER_TYPE_NVMM;
	bp->hdr.loadflags |= LOADFLAGS_LOADED_HIGH;
	bp->hdr.cmd_line_ptr = CMDLINE_ADDR;
	bp->hdr.code32_start = KERN_ADDR;
	snprintf((char *)ctx->mem + CMDLINE_ADDR, page_size, "%s", opts->cmdline);

	bp->e820_entries = 3;
	bp->e820_table[0].addr = 0;
	bp->e820_table[0].size = EBDA_START;
	bp->e820_table[0].type = E820_RAM;
	
	bp->e820_table[1].addr = EBDA_START;
	bp->e820_table[1].size = EBDA_SIZE;
	bp->e820_table[1].type = E820_RESERVED;
	
	bp->e820_table[2].addr = HIGH_RAM_START;
	if (opts->mem_size <= MMIO_HOLE_START) {
		bp->e820_table[2].size = opts->mem_size - HIGH_RAM_START;
		bp->e820_table[2].type = E820_RAM;
	} else {
		bp->e820_table[2].size = MMIO_HOLE_START - HIGH_RAM_START;
		bp->e820_table[2].type = E820_RAM;

		bp->e820_entries = 4;
		bp->e820_table[3].addr = FOUR_GB;
		bp->e820_table[3].size = opts->mem_size - MMIO_HOLE_START;
		bp->e820_table[3].type = E820_RAM;
	}

	setup_mptable(ctx, opts->nvcpu);
}

/**
 * vm_arch_post_init() - Perform post-vCPU x86_64 initialization and EPT pre-faulting.
 * @opts: Pointer to VMM configuration options.
 * @ctx: Pointer to KVM VM context.
 */
void vm_arch_post_init(struct vmm_opts *opts, struct kvm_ctx *ctx)
{
	uint64_t low_size;

	if (ctx->nvcpu <= 0 || ctx->vcpus[0].vcpu_fd < 0)
		return;

	low_size = (opts->mem_size <= MMIO_HOLE_START) ?
		   opts->mem_size : MMIO_HOLE_START;
	prefault_guest_memory(ctx->vcpus[0].vcpu_fd, 0, low_size);

	if (opts->mem_size > MMIO_HOLE_START) {
		prefault_guest_memory(ctx->vcpus[0].vcpu_fd, FOUR_GB,
				      opts->mem_size - MMIO_HOLE_START);
	}
}

/**
 * uart_irq_pulse() - Set COM1 (IRQ 4) interrupt line level.
 * @ctx: Pointer to KVM VM context.
 * @level: IRQ line level (1 to assert, 0 to deassert).
 */
void uart_irq_pulse(struct kvm_ctx *ctx, int level)
{
	struct kvm_irq_level irq_level;

	irq_level.irq = COM1_IRQ;
	irq_level.level = level;
	ioctl(ctx->vm_fd, KVM_IRQ_LINE, &irq_level);
}

/**
 * vm_arch_uart_rx() - Handle incoming UART RX data for COM1.
 * @ctx: Pointer to KVM VM context.
 */
void vm_arch_uart_rx(struct kvm_ctx *ctx)
{
	if (com1_regs[UART_IER_REG] & UART_IER_RDI)
		pulse_irq(ctx, COM1_IRQ);
}

static void setup_long_mode(struct vcpu_ctx *vcpu)
{
	struct kvm_segment seg;
	struct kvm_sregs sregs;
	uint64_t *pml4;
	uint64_t *pdp;
	uint64_t *gdt;
	uint64_t *pd;
	int j;
	int i;

	if (ioctl(vcpu->vcpu_fd, KVM_GET_SREGS, &sregs) < 0)
		die("KVM_GET_SREGS");

	gdt = (uint64_t *)((uint8_t *)vcpu->ctx->mem + GDT_ADDR);
	gdt[0] = 0;
	gdt[1] = GDT_CODE64_ENT;
	gdt[2] = GDT_DATA64_ENT;
	
	sregs.gdt.base = GDT_ADDR;
	sregs.gdt.limit = GDT_LIMIT;

	memset(&seg, 0, sizeof(seg));
	seg.base = 0;
	seg.limit = 0xffffffff;
	seg.present = 1;
	seg.s = 1;
	seg.g = 1;

	seg.selector = BOOT_CS;
	seg.type = SEG_TYPE_CODE64;
	seg.l = 1;
	seg.db = 0;
	sregs.cs = seg;

	seg.selector = BOOT_DS;
	seg.type = SEG_TYPE_DATA;
	seg.l = 0;
	seg.db = 1;
	sregs.ds = seg;
	sregs.es = seg;
	sregs.fs = seg;
	sregs.gs = seg;
	sregs.ss = seg;
	sregs.tr.present = 1;

	pml4 = (uint64_t *)((uint8_t *)vcpu->ctx->mem + PML4_ADDR);
	pdp = (uint64_t *)((uint8_t *)vcpu->ctx->mem + PDP_ADDR);
	pd = (uint64_t *)((uint8_t *)vcpu->ctx->mem + PD_ADDR);

	memset(pml4, 0, X86_PAGE_SIZE);
	memset(pdp, 0, X86_PAGE_SIZE);
	memset(pd, 0, X86_PAGE_SIZE * 4);

	uint64_t max_phys = (vcpu->ctx->mem_size > MMIO_HOLE_START) ?
			    (FOUR_GB + vcpu->ctx->mem_size -
			     MMIO_HOLE_START) : vcpu->ctx->mem_size;
	int num_gigas = (int)((max_phys + SZ_1G - 1) / SZ_1G);
	if (num_gigas < 4)
		num_gigas = 4;
	if (num_gigas > 512)
		num_gigas = 512;

	pml4[0] = PDP_ADDR | PAGE_PRESENT_RW;
	for (i = 0; i < 4; i++) {
		pdp[i] = (PD_ADDR + i * X86_PAGE_SIZE) | PAGE_PRESENT_RW;
		for (j = 0; j < 512; j++)
			pd[i * 512 + j] = (uint64_t)(i * 512 + j) *
					  PDE64_PAGE_SIZE | PDE64_FLAGS;
	}
	for (i = 4; i < num_gigas; i++)
		pdp[i] = (uint64_t)i * SZ_1G | PDE64_FLAGS;

	sregs.cr3 = PML4_ADDR;
	sregs.cr4 = CR4_DEFAULT;
	sregs.cr0 = CR0_DEFAULT;
	sregs.efer = EFER_DEFAULT;
	
	if (ioctl(vcpu->vcpu_fd, KVM_SET_SREGS, &sregs) < 0)
		die("KVM_SET_SREGS");
}

/**
 * vcpu_arch_init() - Configure x86_64 vCPU CPUID and initial registers.
 * @opts: Pointer to VMM configuration options.
 * @vcpu: Pointer to vCPU context to initialize.
 */
void vcpu_arch_init(struct vmm_opts *opts, struct vcpu_ctx *vcpu)
{
	if (opts->is_resume)
		return;

	struct kvm_regs regs;
	long page_size = sysconf(_SC_PAGESIZE);

	if (cached_cpuid) {
		for (int i = 0; i < (int)cached_cpuid->nent; i++) {
			struct kvm_cpuid_entry2 *entry =
				&cached_cpuid->entries[i];

			if (entry->function == 1) {
				entry->ebx = (entry->ebx & 0x00ffffff) |
					     ((uint32_t)vcpu->id << 24);
			} else if (entry->function == 0x0b ||
				   entry->function == 0x1f) {
				entry->edx = (uint32_t)vcpu->id;
			}
		}
		if (ioctl(vcpu->vcpu_fd, KVM_SET_CPUID2, cached_cpuid) < 0)
			die("KVM_SET_CPUID2");
	}

	setup_long_mode(vcpu);
	
	memset(&regs, 0, sizeof(regs));
	regs.rip = KERN_ADDR + KERNEL_ENTRY_OFFSET;
	regs.rsi = BOOT_ADDR;
	regs.rsp = opts->mem_size - page_size;
	regs.rflags = X86_RFLAGS_DEFAULT;
	ioctl(vcpu->vcpu_fd, KVM_SET_REGS, &regs);
	
	if (vcpu->id > 0) {
		struct kvm_mp_state mp_state = { .mp_state = KVM_MP_STATE_UNINITIALIZED };
		ioctl(vcpu->vcpu_fd, KVM_SET_MP_STATE, &mp_state);
	}
}

static void com1_in(struct vcpu_ctx *vcpu, uint8_t *data)
{
	uint16_t port = vcpu->run->io.port;
	int count = vcpu->run->io.count;
	uint8_t offset = port - COM1_PORT;

	if (port < COM1_PORT || port >= COM1_PORT + COM1_REG_COUNT)
		return;

	memset(data, 0, vcpu->run->io.size * count);

	for (int i = 0; i < count; i++) {
		switch (offset) {
		case UART_RX_REG:
			if (com1_regs[UART_LCR_REG] & UART_LCR_DLAB) {
				*data = com1_regs[UART_RX_REG];
				break;
			}
			if (console_rx_pop(data) != 0)
				*data = 0;
			break;
		case UART_IER_REG:
			*data = com1_regs[UART_IER_REG];
			break;
		case UART_IIR_REG:
			if (console_rx_has_data()) {
				*data = UART_IIR_RDI;
			} else if (com1_thre_int_pending) {
				*data = UART_IIR_THRE;
				com1_thre_int_pending = 0;
			} else {
				*data = UART_IIR_NO_INT;
			}
			break;
		case UART_LSR_REG:
			*data = COM1_LSR_TX_EMPTY;
			if (console_rx_has_data())
				*data |= UART_LSR_DR;
			break;
		case UART_MSR_REG:
			*data = UART_MSR_DEFAULT;
			break;
		default:
			*data = com1_regs[offset];
			break;
		}
		data += vcpu->run->io.size;
	}
}

static void com1_out(struct vcpu_ctx *vcpu, const uint8_t *data)
{
	uint16_t port = vcpu->run->io.port;
	int count = vcpu->run->io.count;

	if (port == COM1_PORT) {
		if (com1_regs[UART_LCR_REG] & UART_LCR_DLAB) {
			com1_regs[UART_RX_REG] = *data;
		} else {
			for (int i = 0; i < count; i++) {
				unsigned char c = *data;
				ssize_t ret = write(STDOUT_FILENO, &c, 1);
				(void)ret;
				data += vcpu->run->io.size;
			}
			fflush(stdout);
		}

		if (com1_regs[UART_IER_REG] & UART_IER_THRE) {
			com1_thre_int_pending = 1;
			pulse_irq(vcpu->ctx, COM1_IRQ);
		}
	} else if (port > COM1_PORT && port < COM1_PORT + COM1_REG_COUNT) {
		for (int i = 0; i < count; i++) {
			uint8_t off = port - COM1_PORT;
			com1_regs[off] = *data;
			if (off == UART_IER_REG &&
			    !(com1_regs[UART_LCR_REG] & UART_LCR_DLAB) &&
			    (*data & UART_IER_RDI) && console_rx_has_data()) {
				pulse_irq(vcpu->ctx, COM1_IRQ);
			}
			data += vcpu->run->io.size;
		}
	}
}

/**
 * handle_io() - Emulate PIO accesses for COM1 UART and panic ports.
 * @vcpu: Pointer to vCPU context that exited.
 */
static void handle_io(struct vcpu_ctx *vcpu)
{
	uint8_t *data;

	data = (uint8_t *)vcpu->run + vcpu->run->io.data_offset;

	if (vcpu->run->io.direction == KVM_EXIT_IO_IN)
		com1_in(vcpu, data);
	else if (vcpu->run->io.direction == KVM_EXIT_IO_OUT)
		com1_out(vcpu, data);
}

/**
 * handle_shutdown() - Handle triple fault or guest shutdown exit.
 * @vcpu: Pointer to vCPU context that exited.
 */
static void handle_shutdown(struct vcpu_ctx *vcpu)
{
	struct kvm_regs r;
	ioctl(vcpu->vcpu_fd, KVM_GET_REGS, &r);
	fprintf(stderr, "\n[NVMM] Shutdown (Triple Fault) at RIP: 0x%llx\n",
	        (unsigned long long)r.rip);
	vm_teardown(vcpu->ctx);
	exit(1);
}

/**
 * handle_arch_exit() - Dispatch x86_64 KVM exit reason.
 * @vcpu: Pointer to vCPU context that exited.
 */
void handle_arch_exit(struct vcpu_ctx *vcpu)
{
	switch (vcpu->run->exit_reason) {
	case KVM_EXIT_IO:
		handle_io(vcpu);
		break;
	case KVM_EXIT_SHUTDOWN:
		handle_shutdown(vcpu);
		break;
	default:
		break;
	}
}

/**
 * vm_arch_teardown() - Release x86_64 architecture-specific resources.
 * @ctx: Pointer to KVM VM context.
 */
void vm_arch_teardown(struct kvm_ctx *ctx __maybe_unused)
{
	if (cached_cpuid) {
		free(cached_cpuid);
		cached_cpuid = NULL;
	}
}
