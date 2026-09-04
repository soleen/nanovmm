#include "arm64_fdt.h"
#include "nvmm.h"
#include <endian.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Flattened Device Tree (FDT) Tokens */
#define FDT_MAGIC		0xd00dfeed
#define FDT_BEGIN_NODE		0x00000001
#define FDT_END_NODE		0x00000002
#define FDT_PROP		0x00000003
#define FDT_NOP			0x00000004
#define FDT_END			0x00000009

#define FDT_VERSION		17
#define FDT_LAST_COMP_VERSION	16
#define FDT_HEADER_SIZE		40
#define FDT_RESERVED_MAP_OFF	FDT_HEADER_SIZE
#define FDT_RESERVED_MAP_SIZE	16
#define FDT_STRUCT_OFF		(FDT_RESERVED_MAP_OFF + FDT_RESERVED_MAP_SIZE)
#define FDT_STRINGS_MAX_SIZE	4096

#define RAM_BASE		0x40000000ULL
#define GIC_PHANDLE		1
#define CLOCK_PHANDLE		2
#define GIC_DIST_BASE		0x08000000
#define GIC_DIST_SIZE		0x00010000
#define GIC_REDIST_BASE		0x080A0000
#define GIC_REDIST_SIZE		(0x00020000 * NVMM_MAX_VCPUS)
#define UART_BASE		0x09000000
#define UART_SIZE		0x00001000
#define UART_IRQ		33
#define SPI_IRQ_OFFSET		32
#define UART_CLK_FREQ_HZ	24000000

#define GIC_FDT_IRQ_NUM_CELLS	3
#define GIC_FDT_IRQ_TYPE_SPI	0
#define GIC_FDT_IRQ_TYPE_PPI	1
#define GIC_FDT_IRQ_LEVEL_HI	4
#define GIC_FDT_IRQ_LEVEL_LOW	8

#define ARM_TIMER_SECURE_PPI	13
#define ARM_TIMER_NONSEC_PPI	14
#define ARM_TIMER_VIRT_PPI	11
#define ARM_TIMER_HYP_PPI	10

struct fdt_builder {
	uint8_t *buf;
	size_t max_size;
	size_t struct_off;
	size_t strings_size;
};

static void fdt_check_bounds(struct fdt_builder *b, size_t need_struct,
			     size_t need_strings)
{
	size_t str_base_off = b->max_size - FDT_STRINGS_MAX_SIZE;

	if (b->struct_off + need_struct >= str_base_off ||
	    b->strings_size + need_strings >= FDT_STRINGS_MAX_SIZE) {
		fprintf(stderr, "[NVMM FATAL] FDT buffer overflow\n");
		exit(1);
	}
}

static void fdt_put_u32(struct fdt_builder *b, uint32_t val)
{
	uint32_t be = htobe32(val);

	fdt_check_bounds(b, 4, 0);
	memcpy(b->buf + b->struct_off, &be, 4);
	b->struct_off += 4;
}

static void fdt_begin_node(struct fdt_builder *b, const char *name)
{
	size_t len = strlen(name) + 1;
	size_t aligned_len = ALIGN_UP(len, 4);

	fdt_check_bounds(b, 4 + aligned_len, 0);
	fdt_put_u32(b, FDT_BEGIN_NODE);
	memcpy(b->buf + b->struct_off, name, len);
	b->struct_off += aligned_len;
}

static void fdt_end_node(struct fdt_builder *b)
{
	fdt_put_u32(b, FDT_END_NODE);
}

static uint32_t fdt_add_string(struct fdt_builder *b, const char *str)
{
	uint8_t *str_base = b->buf + b->max_size - FDT_STRINGS_MAX_SIZE;

	for (size_t i = 0; i < b->strings_size;) {
		if (strcmp((char *)str_base + i, str) == 0)
			return (uint32_t)i;
		i += strlen((char *)str_base + i) + 1;
	}
	size_t len = strlen(str) + 1;
	fdt_check_bounds(b, 0, len);
	uint32_t off = (uint32_t)b->strings_size;

	memcpy(str_base + off, str, len);
	b->strings_size += len;
	return off;
}

static void fdt_prop(struct fdt_builder *b, const char *name,
		     const void *val, size_t len)
{
	uint32_t nameoff = fdt_add_string(b, name);
	size_t aligned_val_len = (len > 0) ? ALIGN_UP(len, 4) : 0;

	fdt_check_bounds(b, 12 + aligned_val_len, 0);
	fdt_put_u32(b, FDT_PROP);
	fdt_put_u32(b, (uint32_t)len);
	fdt_put_u32(b, nameoff);
	if (len > 0) {
		memcpy(b->buf + b->struct_off, val, len);
		b->struct_off += aligned_val_len;
	}
}

static void fdt_prop_u32(struct fdt_builder *b, const char *name, uint32_t val)
{
	uint32_t be = htobe32(val);

	fdt_prop(b, name, &be, 4);
}

static void fdt_prop_u64(struct fdt_builder *b, const char *name, uint64_t val)
{
	uint64_t be = htobe64(val);

	fdt_prop(b, name, &be, 8);
}

static void fdt_prop_str(struct fdt_builder *b, const char *name,
			 const char *str)
{
	fdt_prop(b, name, str, strlen(str) + 1);
}

static void fdt_init(struct fdt_builder *b, void *buf, size_t max_size)
{
	b->buf = (uint8_t *)buf;
	b->max_size = max_size;
	b->struct_off = FDT_STRUCT_OFF;
	b->strings_size = 0;
	memset(b->buf, 0, max_size);
}

static size_t fdt_finish(struct fdt_builder *b)
{
	fdt_put_u32(b, FDT_END);
	size_t struct_size = b->struct_off - FDT_STRUCT_OFF;
	size_t strings_start = ALIGN_UP(b->struct_off, 16);
	uint8_t *str_base = b->buf + b->max_size - FDT_STRINGS_MAX_SIZE;

	memcpy(b->buf + strings_start, str_base, b->strings_size);
	size_t total_size = strings_start + b->strings_size;

	uint32_t *hdr = (uint32_t *)b->buf;

	hdr[0] = htobe32(FDT_MAGIC);
	hdr[1] = htobe32((uint32_t)total_size);
	hdr[2] = htobe32(FDT_STRUCT_OFF);
	hdr[3] = htobe32((uint32_t)strings_start);
	hdr[4] = htobe32(FDT_RESERVED_MAP_OFF);
	hdr[5] = htobe32(FDT_VERSION);
	hdr[6] = htobe32(FDT_LAST_COMP_VERSION);
	hdr[7] = htobe32(0);
	hdr[8] = htobe32((uint32_t)b->strings_size);
	hdr[9] = htobe32((uint32_t)struct_size);

	return total_size;
}

static void write_chosen_node(struct fdt_builder *b, struct vmm_opts *opts,
			      uint64_t initrd_addr, size_t initrd_size)
{
	fdt_begin_node(b, "chosen");
	fdt_prop_str(b, "bootargs", opts->cmdline ? opts->cmdline : "");
	fdt_prop_str(b, "stdout-path", "/pl011@9000000");
	if (initrd_size > 0) {
		fdt_prop_u64(b, "linux,initrd-start", initrd_addr);
		fdt_prop_u64(b, "linux,initrd-end", initrd_addr + initrd_size);
	}
	fdt_end_node(b);
}

static void write_psci_node(struct fdt_builder *b)
{
	fdt_begin_node(b, "psci");
	fdt_prop_str(b, "compatible", "arm,psci-0.2");
	fdt_prop_str(b, "method", "hvc");
	fdt_end_node(b);
}

static void write_cpu_nodes(struct fdt_builder *b, int num_vcpus)
{
	fdt_begin_node(b, "cpus");
	fdt_prop_u32(b, "#address-cells", 1);
	fdt_prop_u32(b, "#size-cells", 0);

	for (int c = 0; c < num_vcpus; c++) {
		char name[32];

		snprintf(name, sizeof(name), "cpu@%d", c);
		fdt_begin_node(b, name);
		fdt_prop_str(b, "device_type", "cpu");
		fdt_prop_str(b, "compatible", "arm,arm-v8");
		fdt_prop_str(b, "enable-method", "psci");
		fdt_prop_u32(b, "reg", c);
		fdt_end_node(b);
	}
	fdt_end_node(b);
}

static void write_memory_node(struct fdt_builder *b, size_t mem_size)
{
	char mem_name[32];
	uint64_t mem_reg[2] = { htobe64(RAM_BASE), htobe64(mem_size) };

	snprintf(mem_name, sizeof(mem_name), "memory@%llx",
		 (unsigned long long)RAM_BASE);
	fdt_begin_node(b, mem_name);
	fdt_prop_str(b, "device_type", "memory");
	fdt_prop(b, "reg", mem_reg, sizeof(mem_reg));
	fdt_end_node(b);
}

static void write_gic_node(struct fdt_builder *b)
{
	char gic_name[32];
	uint64_t gic_reg[4] = {
		htobe64(GIC_DIST_BASE), htobe64(GIC_DIST_SIZE),
		htobe64(GIC_REDIST_BASE), htobe64(GIC_REDIST_SIZE)
	};

	snprintf(gic_name, sizeof(gic_name), "interrupt-controller@%x",
		 GIC_DIST_BASE);
	fdt_begin_node(b, gic_name);
	fdt_prop_str(b, "compatible", "arm,gic-v3");
	fdt_prop_u32(b, "#interrupt-cells", GIC_FDT_IRQ_NUM_CELLS);
	fdt_prop(b, "interrupt-controller", NULL, 0);
	fdt_prop_u32(b, "phandle", GIC_PHANDLE);
	fdt_prop(b, "reg", gic_reg, sizeof(gic_reg));
	fdt_end_node(b);
}

static void write_timer_node(struct fdt_builder *b)
{
	uint64_t timer_freq = 0;

	asm volatile("mrs %0, cntfrq_el0" : "=r"(timer_freq));
	if (timer_freq == 0)
		timer_freq = 62500000ULL;

	uint32_t timer_irqs[12] = {
		htobe32(GIC_FDT_IRQ_TYPE_PPI), htobe32(ARM_TIMER_SECURE_PPI),
		htobe32(GIC_FDT_IRQ_LEVEL_LOW),
		htobe32(GIC_FDT_IRQ_TYPE_PPI), htobe32(ARM_TIMER_NONSEC_PPI),
		htobe32(GIC_FDT_IRQ_LEVEL_LOW),
		htobe32(GIC_FDT_IRQ_TYPE_PPI), htobe32(ARM_TIMER_VIRT_PPI),
		htobe32(GIC_FDT_IRQ_LEVEL_LOW),
		htobe32(GIC_FDT_IRQ_TYPE_PPI), htobe32(ARM_TIMER_HYP_PPI),
		htobe32(GIC_FDT_IRQ_LEVEL_LOW)
	};

	fdt_begin_node(b, "timer");
	fdt_prop_str(b, "compatible", "arm,armv8-timer");
	fdt_prop_u32(b, "clock-frequency", (uint32_t)timer_freq);
	fdt_prop(b, "interrupts", timer_irqs, sizeof(timer_irqs));
	fdt_end_node(b);
}

static void write_clocks_node(struct fdt_builder *b)
{
	fdt_begin_node(b, "apb-pclk");
	fdt_prop_str(b, "compatible", "fixed-clock");
	fdt_prop_u32(b, "#clock-cells", 0);
	fdt_prop_u32(b, "clock-frequency", UART_CLK_FREQ_HZ);
	fdt_prop_str(b, "clock-output-names", "clk24mhz");
	fdt_prop_u32(b, "phandle", CLOCK_PHANDLE);
	fdt_end_node(b);
}

static void write_uart_node(struct fdt_builder *b)
{
	char uart_name[32];
	const char pl011_compat[] = "arm,pl011\0arm,primecell";
	const char pl011_clknames[] = "uartclk\0apb_pclk";
	uint64_t uart_reg[2] = { htobe64(UART_BASE), htobe64(UART_SIZE) };
	uint32_t uart_irq[3] = {
		htobe32(GIC_FDT_IRQ_TYPE_SPI),
		htobe32(UART_IRQ - SPI_IRQ_OFFSET),
		htobe32(GIC_FDT_IRQ_LEVEL_HI)
	};
	uint32_t uart_clks[2] = {
		htobe32(CLOCK_PHANDLE), htobe32(CLOCK_PHANDLE)
	};

	snprintf(uart_name, sizeof(uart_name), "pl011@%x", UART_BASE);
	fdt_begin_node(b, uart_name);
	fdt_prop(b, "compatible", pl011_compat, sizeof(pl011_compat));
	fdt_prop(b, "reg", uart_reg, sizeof(uart_reg));
	fdt_prop(b, "interrupts", uart_irq, sizeof(uart_irq));
	fdt_prop(b, "clocks", uart_clks, sizeof(uart_clks));
	fdt_prop(b, "clock-names", pl011_clknames, sizeof(pl011_clknames));
	fdt_end_node(b);
}

size_t arm64_fdt_setup(void *dtb_dest, struct vmm_opts *opts,
		       uint64_t initrd_addr, size_t initrd_size)
{
	struct fdt_builder b;
	int num_vcpus = (opts->nvcpu > 0) ? opts->nvcpu : 1;

	if (num_vcpus > NVMM_MAX_VCPUS)
		num_vcpus = NVMM_MAX_VCPUS;

	fdt_init(&b, dtb_dest, 0x200000);

	fdt_begin_node(&b, "");
	fdt_prop_u32(&b, "#address-cells", 2);
	fdt_prop_u32(&b, "#size-cells", 2);
	fdt_prop_u32(&b, "interrupt-parent", GIC_PHANDLE);

	write_chosen_node(&b, opts, initrd_addr, initrd_size);
	write_psci_node(&b);
	write_cpu_nodes(&b, num_vcpus);
	write_memory_node(&b, opts->mem_size);
	write_gic_node(&b);
	write_timer_node(&b);
	write_clocks_node(&b);
	write_uart_node(&b);

	fdt_end_node(&b);

	return fdt_finish(&b);
}
