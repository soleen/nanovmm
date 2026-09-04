#include "nvmm.h"
#include "arm64_fdt.h"
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <linux/kvm.h>

#ifndef KVM_REG_ARM_CORE
#define KVM_REG_ARM_CORE	0x0010000000000000ULL
#endif
#ifndef KVM_REG_ARM_CORE_REG
#define KVM_REG_ARM_CORE_REG(x) \
	(KVM_REG_ARM64 | KVM_REG_SIZE_U64 | KVM_REG_ARM_CORE | ((x) / 4))
#endif
#define KVM_REG_ARM_PC \
	(KVM_REG_ARM64 | KVM_REG_SIZE_U64 | KVM_REG_ARM_CORE | (32 * 2))

/* ARM64 Memory Map */
#define RAM_BASE		0x40000000ULL
#define KERN_ADDR		(RAM_BASE + 0x200000)
/* Place DTB at 80MB, Initrd at 90MB to avoid overwriting kernel Image */
#define DTB_ADDR		(RAM_BASE + 0x5000000)
#define INITRD_ADDR		(RAM_BASE + 0x5A00000)

/* ARM64 Generic Interrupt Controller (GIC) */
#define ARM64_MAX_VCPUS		NVMM_MAX_VCPUS
#define GIC_DIST_BASE		0x08000000
#define GIC_DIST_SIZE		0x00010000
#define GIC_REDIST_BASE		0x080A0000
#define GIC_REDIST_SIZE		(0x00020000 * ARM64_MAX_VCPUS)

/* ARM64 PL011 UART */
#define UART_BASE		0x09000000
#define UART_SIZE		0x00001000
#define UART_IRQ		33

/* Core Registers */
#define KVM_ARM_VCPU_INIT	_IOW(KVMIO, 0xae, struct kvm_vcpu_init)
#define KVM_ARM_PREFERRED_TARGET _IOR(KVMIO, 0xaf, struct kvm_vcpu_init)

#define KVM_REG_ARM_X0 \
	(KVM_REG_ARM64 | KVM_REG_SIZE_U64 | KVM_REG_ARM_CORE | (0 * 2))
#define KVM_REG_ARM_X1 \
	(KVM_REG_ARM64 | KVM_REG_SIZE_U64 | KVM_REG_ARM_CORE | (1 * 2))
#define KVM_REG_ARM_X2 \
	(KVM_REG_ARM64 | KVM_REG_SIZE_U64 | KVM_REG_ARM_CORE | (2 * 2))
#define KVM_REG_ARM_X3 \
	(KVM_REG_ARM64 | KVM_REG_SIZE_U64 | KVM_REG_ARM_CORE | (3 * 2))
#define KVM_REG_ARM_PSTATE \
	(KVM_REG_ARM64 | KVM_REG_SIZE_U64 | KVM_REG_ARM_CORE | (33 * 2))

#define PSR_MODE_EL1h		0x00000005
#define PSR_F_BIT		0x00000040
#define PSR_I_BIT		0x00000080
#define PSR_A_BIT		0x00000100
#define PSR_D_BIT		0x00000200

#define PL011_DR_OFFSET		0x000
#define PL011_FR_OFFSET		0x018
#define PL011_FR_RXFE		(1 << 4)
#define PL011_FR_TXFF		(1 << 5)
#define PL011_FR_RXFF		(1 << 6)
#define PL011_FR_TXFE		(1 << 7)
#define PL011_IMSC_OFFSET	0x038
#define PL011_RIS_OFFSET	0x03c
#define PL011_MIS_OFFSET	0x040
#define PL011_ICR_OFFSET	0x044
#define PL011_PERIPH_ID_START	0xfe0
#define PL011_PERIPH_ID_END	0xffc
#define PL011_INT_RXIS		(1 << 4)
#define PL011_INT_RTIS		(1 << 6)
#define PL011_INT_ALL		(PL011_INT_RXIS | PL011_INT_RTIS)

struct kvm_vcpu_init vcpu_init_config;
static uint32_t pl011_imsc = 0;

/**
 * create_dtb() - Create in-memory Device Tree Blob for ARM64 guest.
 * @opts: Pointer to VMM configuration options.
 * @ctx: Pointer to KVM VM context.
 * @initrd_addr: Guest physical address of loaded initrd image.
 * @initrd_size: Size in bytes of loaded initrd image.
 */
static void create_dtb(struct vmm_opts *opts, struct kvm_ctx *ctx,
		       uint64_t initrd_addr, size_t initrd_size)
{
	uint8_t *dtb = (uint8_t *)ctx->mem + (DTB_ADDR - RAM_BASE);

	arm64_fdt_setup(dtb, opts, initrd_addr, initrd_size);
}

static int gic_fd = -1;

static inline int vgic_dev_attr(uint32_t group, uint64_t attr,
				void *addr, int is_set)
{
	struct kvm_device_attr dev_attr = {
		.group = group,
		.attr = attr,
		.addr = (uint64_t)addr,
	};
	return ioctl(gic_fd,
		     is_set ? KVM_SET_DEVICE_ATTR : KVM_GET_DEVICE_ATTR,
		     &dev_attr);
}

/**
 * vm_arch_init() - Initialize ARM64 VM memory map, GICv3, and kernel/DTB.
 * @opts: Pointer to VMM configuration options.
 * @ctx: Pointer to KVM VM context.
 *
 * Configures the in-kernel ARM GICv3 interrupt controller, loads the flat
 * Linux Image and initramfs into guest memory, and generates an in-memory
 * Device Tree Blob (DTB) describing the virtual hardware.
 */
void vm_arch_init(struct vmm_opts *opts, struct kvm_ctx *ctx)
{
	size_t initrd_size = 0;

	/* Setup RAM */
	set_user_mem_region(ctx->vm_fd, 0, RAM_BASE, opts->mem_size, ctx->mem,
			    ctx->ram_fd, 0);
	printf("[NVMM_MEM] slot=0 gpa=0x%llx hva=0x%llx size=0x%llx\n",
	       (unsigned long long)RAM_BASE,
	       (unsigned long long)(uintptr_t)ctx->mem,
	       (unsigned long long)opts->mem_size);
	fflush(stdout);

	/* Create VGIC V3 Device (Must happen before vCPU creation) */
	struct kvm_create_device dev = { .type = KVM_DEV_TYPE_ARM_VGIC_V3 };
	uint64_t gic_dist_base = GIC_DIST_BASE;
	uint64_t gic_redist_base = GIC_REDIST_BASE;

	if (ioctl(ctx->vm_fd, KVM_CREATE_DEVICE, &dev) < 0)
		die("KVM_CREATE_DEVICE (VGIC_V3)");

	gic_fd = dev.fd;
	ctx->gic_fd = dev.fd;

	if (vgic_dev_attr(KVM_DEV_ARM_VGIC_GRP_ADDR,
			  KVM_VGIC_V3_ADDR_TYPE_DIST,
			  &gic_dist_base, 1) < 0)
		die("KVM_SET_DEVICE_ATTR (VGIC_V3_ADDR_TYPE_DIST)");
	if (vgic_dev_attr(KVM_DEV_ARM_VGIC_GRP_ADDR,
			  KVM_VGIC_V3_ADDR_TYPE_REDIST,
			  &gic_redist_base, 1) < 0)
		die("KVM_SET_DEVICE_ATTR (KVM_VGIC_V3_ADDR_TYPE_REDIST)");

	/* Get preferred vCPU target for init */
	if (ioctl(ctx->vm_fd, KVM_ARM_PREFERRED_TARGET, &vcpu_init_config) < 0)
		die("KVM_ARM_PREFERRED_TARGET");

	/* Mandatory: Enable PSCI 0.2 for CPU power management/boot */
	vcpu_init_config.features[0] |= (1 << KVM_ARM_VCPU_PSCI_0_2);

	if (opts->is_resume || !opts->kernel_path)
		return;

	/* Load Kernel Image (Flat binary on ARM64) */
	if (load_file_into_mem(opts->kernel_path,
			       (uint8_t *)ctx->mem + (KERN_ADDR - RAM_BASE),
			       opts->mem_size - (KERN_ADDR - RAM_BASE)) < 0)
		die("load kernel Image");

	/* Load Initrd */
	if (opts->initrd_path) {
		ssize_t sz;

		sz = load_file_into_mem(opts->initrd_path,
					(uint8_t *)ctx->mem +
					(INITRD_ADDR - RAM_BASE),
					opts->mem_size -
					(INITRD_ADDR - RAM_BASE));
		if (sz < 0)
			die("load initrd payload");
		initrd_size = (size_t)sz;
	}

	/* Generate and load DTB */
	create_dtb(opts, ctx, INITRD_ADDR, initrd_size);
}

/**
 * uart_irq_pulse() - Set PL011 UART SPI interrupt line level.
 * @ctx: Pointer to KVM VM context.
 * @level: IRQ line level (1 to assert, 0 to deassert).
 */
void uart_irq_pulse(struct kvm_ctx *ctx, int level)
{
	struct kvm_irq_level irq_lvl;
	/* On ARM64, SPIs must be encoded with the type shifted to top bits.
	 * The absolute IRQ number (33) is used.
	 */
	uint32_t irq = (KVM_ARM_IRQ_TYPE_SPI << KVM_ARM_IRQ_TYPE_SHIFT) | UART_IRQ;

	irq_lvl.irq = irq;
	irq_lvl.level = level;
	if (ioctl(ctx->vm_fd, KVM_IRQ_LINE, &irq_lvl) < 0) {
		perror("KVM_IRQ_LINE");
	}
}

/**
 * vm_arch_uart_rx() - Handle incoming UART RX data for PL011.
 * @ctx: Pointer to KVM VM context.
 */
void vm_arch_uart_rx(struct kvm_ctx *ctx)
{
	if (pl011_imsc & (PL011_INT_RXIS | PL011_INT_RTIS)) {
		uart_irq_pulse(ctx, 1);
		uart_irq_pulse(ctx, 0);
	}
}

/**
 * vm_arch_post_init() - Finalize GICv3 device.
 * @opts: Pointer to VMM configuration options.
 * @ctx: Pointer to KVM VM context.
 *
 * Must be called after all vCPU file descriptors are created.
 * Finalizes the in-kernel GICv3 device.
 */
void vm_arch_post_init(struct vmm_opts *opts, struct kvm_ctx *ctx)
{
	struct kvm_device_attr attr;

	/* Finalize VGIC V3 (Must happen after vCPU creation) */
	attr.group = KVM_DEV_ARM_VGIC_GRP_CTRL;
	attr.attr = KVM_DEV_ARM_VGIC_CTRL_INIT;
	attr.addr = 0;
	if (ioctl(gic_fd, KVM_SET_DEVICE_ATTR, &attr) < 0)
		die("KVM_SET_DEVICE_ATTR (VGIC_CTRL_INIT)");

	if (ctx->nvcpu > 0 && ctx->vcpus[0].vcpu_fd >= 0)
		prefault_guest_memory(ctx->vcpus[0].vcpu_fd, RAM_BASE,
				      opts->mem_size);

	printf("ARM64 Architecture setup complete.\n");
}

static inline int set_one_reg64(int vcpu_fd, uint64_t reg_id, uint64_t val)
{
	struct kvm_one_reg reg = {
		.id = reg_id,
		.addr = (uint64_t)&val,
	};
	return ioctl(vcpu_fd, KVM_SET_ONE_REG, &reg);
}

/**
 * vcpu_arch_init() - Configure ARM64 vCPU registers, PSCI, and EL1h mode.
 * @opts: Pointer to VMM configuration options.
 * @vcpu: Pointer to vCPU context to initialize.
 */
void vcpu_arch_init(struct vmm_opts *opts __maybe_unused,
		    struct vcpu_ctx *vcpu)
{
	if (opts->is_resume)
		return;

	struct kvm_vcpu_init init_cfg = vcpu_init_config;

	if (vcpu->id > 0)
		init_cfg.features[0] |= (1 << KVM_ARM_VCPU_POWER_OFF);

	if (ioctl(vcpu->vcpu_fd, KVM_ARM_VCPU_INIT, &init_cfg) < 0)
		die("KVM_ARM_VCPU_INIT");

	if (vcpu->id > 0)
		return;

	/* Set PC to kernel entry and x0 to DTB physical address */
	set_one_reg64(vcpu->vcpu_fd, KVM_REG_ARM_PC, KERN_ADDR);
	set_one_reg64(vcpu->vcpu_fd, KVM_REG_ARM_X0, DTB_ADDR);

	/* Clear x1, x2, x3 per boot protocol */
	set_one_reg64(vcpu->vcpu_fd, KVM_REG_ARM_X1, 0);
	set_one_reg64(vcpu->vcpu_fd, KVM_REG_ARM_X2, 0);
	set_one_reg64(vcpu->vcpu_fd, KVM_REG_ARM_X3, 0);

	/* Set PSTATE to EL1h, Mask Interrupts */
	set_one_reg64(vcpu->vcpu_fd, KVM_REG_ARM_PSTATE,
		      PSR_MODE_EL1h | PSR_A_BIT | PSR_I_BIT |
		      PSR_F_BIT | PSR_D_BIT);
}

static void pl011_write(struct vcpu_ctx *vcpu __maybe_unused, uint64_t offset,
			const uint8_t *data, uint32_t len)
{
	if (offset == PL011_DR_OFFSET) {
		uint32_t val = (len == 4) ? *(const uint32_t *)data : data[0];
		unsigned char c = (unsigned char)(val & 0xFF);

		ssize_t ret = write(STDOUT_FILENO, &c, 1);
		(void)ret;
		if (c == '\n' || c == '\r')
			fflush(stdout);
	} else if (offset == PL011_IMSC_OFFSET) {
		pl011_imsc = *(const uint32_t *)data;
		if ((pl011_imsc & (PL011_INT_RXIS | PL011_INT_RTIS)) &&
		    console_rx_has_data()) {
			uart_irq_pulse(vcpu->ctx, 1);
			uart_irq_pulse(vcpu->ctx, 0);
		}
	} else if (offset == PL011_ICR_OFFSET) {
		if (*(const uint32_t *)data & PL011_INT_ALL) {
			uart_irq_pulse(vcpu->ctx, 0);
		}
	}
}

static void pl011_read(struct vcpu_ctx *vcpu __maybe_unused, uint64_t offset,
		       uint8_t *data, uint32_t len)
{
	if (offset == PL011_DR_OFFSET) {
		uint8_t c = 0;
		if (console_rx_pop(&c) == 0)
			data[0] = c;
		else
			data[0] = 0;
	} else if (offset == PL011_FR_OFFSET) {
		uint32_t fr = PL011_FR_TXFE;
		if (!console_rx_has_data())
			fr |= PL011_FR_RXFE;
		*(uint32_t *)data = fr;
	} else if (offset == PL011_IMSC_OFFSET) {
		*(uint32_t *)data = pl011_imsc;
	} else if (offset == PL011_RIS_OFFSET || offset == PL011_MIS_OFFSET) {
		uint32_t ris = 0;
		if (console_rx_has_data())
			ris |= PL011_INT_RXIS | PL011_INT_RTIS;
		if (offset == PL011_MIS_OFFSET)
			*(uint32_t *)data = ris & pl011_imsc;
		else
			*(uint32_t *)data = ris;
	} else if (offset >= PL011_PERIPH_ID_START &&
		   offset <= PL011_PERIPH_ID_END) {
		static const uint8_t amba_id[] = {
			0x11, 0x10, 0x14, 0x00,
			0x0d, 0xf0, 0x05, 0xb1
		};
		int idx = (offset - PL011_PERIPH_ID_START) / 4;

		if (idx >= 0 && idx < 8)
			*(uint32_t *)data = amba_id[idx];
		else
			memset(data, 0, len);
	} else {
		memset(data, 0, len);
	}
}

/**
 * handle_mmio() - Emulate MMIO accesses for PL011 UART and GICv3.
 * @vcpu: Pointer to vCPU context that exited.
 */
static void handle_mmio(struct vcpu_ctx *vcpu)
{
	struct kvm_run *run = vcpu->run;
	uint64_t addr = run->mmio.phys_addr;
	uint8_t *data = run->mmio.data;

	if (addr >= UART_BASE && addr < UART_BASE + UART_SIZE) {
		uint64_t offset = addr - UART_BASE;

		if (run->mmio.is_write)
			pl011_write(vcpu, offset, data, run->mmio.len);
		else
			pl011_read(vcpu, offset, data, run->mmio.len);
	} else if (!run->mmio.is_write) {
		memset(data, 0, run->mmio.len);
	}
}

/**
 * handle_arch_exit() - Dispatch ARM64 KVM exit reason.
 * @vcpu: Pointer to vCPU context that exited.
 */
void handle_arch_exit(struct vcpu_ctx *vcpu)
{
	switch (vcpu->run->exit_reason) {
	case KVM_EXIT_MMIO:
		handle_mmio(vcpu);
		break;
	default:
		/*
		 * KVM_EXIT_HLT (WFI/WFE) is a valid idle state on ARM64
		 * when not handled in-kernel. KVM_EXIT_SYSTEM_EVENT,
		 * KVM_EXIT_FAIL_ENTRY, and KVM_EXIT_INTERNAL_ERROR are
		 * handled in vcpu_thread() before reaching this path.
		 */
		break;
	}
}

/**
 * vm_arch_teardown() - Release ARM64 architecture-specific resources.
 * @ctx: Pointer to KVM VM context.
 */
void vm_arch_teardown(struct kvm_ctx *ctx)
{
	if (ctx && ctx->gic_fd >= 0) {
		close(ctx->gic_fd);
		ctx->gic_fd = -1;
	}
	gic_fd = -1;
}
