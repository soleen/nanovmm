#ifndef ARM64_FDT_H
#define ARM64_FDT_H

#include <stddef.h>
#include <stdint.h>

struct vmm_opts;

/**
 * arm64_fdt_setup() - Instantiate and patch DTB for ARM64 guest.
 * @dtb_dest: Destination pointer in guest RAM.
 * @opts: Pointer to VMM configuration options.
 * @initrd_addr: Guest physical address of loaded initrd image.
 * @initrd_size: Size in bytes of loaded initrd image.
 *
 * Return: Size of DTB blob in bytes.
 */
size_t arm64_fdt_setup(void *dtb_dest, struct vmm_opts *opts,
		       uint64_t initrd_addr, size_t initrd_size);

#endif /* ARM64_FDT_H */
