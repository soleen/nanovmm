#ifndef NVMM_H
#define NVMM_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <unistd.h>
#include <linux/kvm.h>
#include <linux/liveupdate.h>
#include <stdbool.h>
#include <stdatomic.h>

#ifndef __maybe_unused
#define __maybe_unused __attribute__((unused))
#endif

#ifndef ALIGN_UP
#define ALIGN_UP(x, a)		(((x) + ((a) - 1)) & ~((a) - 1))
#endif

/* Size Unit Literals */
#define SZ_1K			1024ULL
#define SZ_1M			(1024ULL * 1024ULL)
#define SZ_1G			(1024ULL * 1024ULL * 1024ULL)
#define HUGEPAGE_2MB_SIZE	(2ULL * SZ_1M)
#define DEFAULT_MEM_SIZE	(128ULL * SZ_1M)

#define NVMM_STATE_MAGIC	0x4e564d4d53544154ULL /* 'NVMMSTAT' */
#define NVMM_STATE_VERSION	3

#define LUO_VM_TOKEN		0x1000ULL
#define LUO_RAM_TOKEN		0x1001ULL
#define LUO_STATE_TOKEN		0x2000ULL
#define LUO_VCPU_BASE_TOKEN	0x10000ULL
#define LUO_CPU_BASE_TOKEN	0x100000ULL

#ifndef KVM_CAP_VCPU_PRESERVE
#define KVM_CAP_VCPU_PRESERVE	252
#endif

#ifndef KVM_CAP_CARETAKER
#define KVM_CAP_CARETAKER	253
#endif

/* Core Device Paths and Names */
#define KVM_DEVICE_PATH		"/dev/kvm"
#define LUO_DEVICE_PATH		"/dev/liveupdate"
#define LUO_RAM_NAME		"guest_memfd"
#define LUO_STATE_NAME		"guest_state"

/* Timeouts and Intervals */
#define LUO_REBOOT_SLEEP_SEC	60

/**
 * set_user_mem_region() - Map a guest physical memory range backed by guest_memfd.
 * @vm_fd: KVM VM file descriptor.
 * @slot: KVM memory slot index.
 * @gpa: Guest physical address.
 * @size: Size of region in bytes.
 * @uaddr: Host userspace pointer backing the region.
 * @guest_memfd: File descriptor of guest_memfd.
 * @guest_memfd_offset: Offset in guest_memfd in bytes.
 */
static inline int set_user_mem_region(int vm_fd, uint32_t slot, uint64_t gpa,
				      uint64_t size, void *uaddr,
				      int guest_memfd, uint64_t guest_memfd_offset)
{
	struct kvm_userspace_memory_region2 region = {
		.slot = slot,
		.flags = (guest_memfd >= 0) ? KVM_MEM_GUEST_MEMFD : 0,
		.guest_phys_addr = gpa,
		.memory_size = size,
		.userspace_addr = (uint64_t)uaddr,
		.guest_memfd = (guest_memfd >= 0) ? (uint32_t)guest_memfd : 0,
		.guest_memfd_offset = guest_memfd_offset,
	};
	return ioctl(vm_fd, KVM_SET_USER_MEMORY_REGION2, &region);
}

#ifndef KVM_PRE_FAULT_MEMORY
struct kvm_pre_fault_memory {
	__u64 gpa;
	__u64 size;
	__u64 flags;
	__u64 padding[5];
};
#define KVM_PRE_FAULT_MEMORY	_IOWR(KVMIO, 0xd5, struct kvm_pre_fault_memory)
#endif

static inline void prefault_guest_memory(int vcpu_fd, uint64_t gpa,
					 uint64_t size)
{
	struct kvm_pre_fault_memory range = {
		.gpa = gpa,
		.size = size,
		.flags = 0,
	};

	while (range.size > 0) {
		if (ioctl(vcpu_fd, KVM_PRE_FAULT_MEMORY, &range) < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			break;
		}
	}
}

#define NVMM_MAX_VCPUS 16
#define NVMM_MAX_PCPUS 1024

#define NVMM_STATE_FLAG_ORPHAN_CPU	(1U << 0)

struct nvmm_machine_state {
	uint64_t magic;
	uint32_t version;
	uint32_t nvcpu;
	uint64_t mem_size;
	uint32_t state_size; /* sizeof(struct nvmm_machine_state) */
	uint32_t flags;
	uint64_t suspend_timestamp_ns;
	uint64_t pre_suspend_time_ns;
	uint64_t pre_suspend_seq;
	uint64_t pre_suspend_hw_ts;
};

struct vcpu_ctx;

struct kvm_ctx {
	size_t mem_size;
	int kvm_fd;
	int vm_fd;
	int gic_fd;
	void *mem;
	int ram_fd;
	struct vcpu_ctx *vcpus;
	int nvcpu;
	int orphan_mode;
	int pcpu_preserve_fds[NVMM_MAX_PCPUS];
	uint64_t transition_ns;
	uint64_t pre_suspend_time_ns;
	uint64_t pre_suspend_seq;
	uint64_t pre_suspend_hw_ts;
	int vcpu_mmap_size;
	int fifo_fd;
	char fifo_path[256];
};

struct vcpu_ctx {
	struct kvm_run *run;
	struct kvm_ctx *ctx;
	pthread_t tid;
	int vcpu_fd;
	int id;
};

struct vmm_opts {
	const char *kernel_path;
	const char *initrd_path;
	const char *cmdline;
	size_t mem_size;
	int nvcpu;
	const char *session_name;
	const char *fifo_path;
	int is_resume;
};

/**
 * full_read() - Read count bytes from fd handling partial reads and EINTR.
 * @fd: File descriptor to read from.
 * @buf: Destination buffer.
 * @count: Number of bytes to read.
 *
 * Return: Total bytes read, or negative error code on failure.
 */
static inline ssize_t full_read(int fd, void *buf, size_t count)
{
	size_t total = 0;

	while (total < count) {
		ssize_t n = read(fd, (char *)buf + total, count - total);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (n == 0)
			break;
		total += n;
	}
	return total;
}

/**
 * load_file_into_mem() - Load an entire file into memory buffer.
 * @path: Path to the file.
 * @dest: Memory destination buffer.
 * @max_size: Maximum allowable size in bytes.
 *
 * Return: Size of file read, or negative error code on failure.
 */
static inline ssize_t load_file_into_mem(const char *path, void *dest,
					 size_t max_size)
{
	struct stat st;
	int fd;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -1;

	if (fstat(fd, &st) < 0) {
		close(fd);
		return -1;
	}

	if ((size_t)st.st_size > max_size) {
		close(fd);
		errno = EFBIG;
		return -1;
	}

	if (full_read(fd, dest, st.st_size) != st.st_size) {
		close(fd);
		return -1;
	}

	close(fd);
	return st.st_size;
}

/**
 * pulse_irq() - Assert and deassert an interrupt line on the VM.
 * @ctx: Pointer to the KVM VM context.
 * @irq: Interrupt line number to pulse.
 */
void pulse_irq(struct kvm_ctx *ctx, int irq);

/**
 * die() - Print error message with errno and terminate execution.
 * @msg: Error description prefix.
 */
void die(const char *msg);

/**
 * vm_suspend() - Pause all vCPU threads.
 * @ctx: Pointer to the KVM VM context.
 * @vcpus: Array of vCPU contexts.
 * @nvcpu: Number of vCPUs.
 */
void vm_suspend(struct kvm_ctx *ctx, struct vcpu_ctx *vcpus, int nvcpu);

/**
 * vm_resume() - Resume vCPU execution.
 * @ctx: Pointer to the KVM VM context.
 * @vcpus: Array of vCPU contexts.
 * @nvcpu: Number of vCPUs.
 */
void vm_resume(struct kvm_ctx *ctx, struct vcpu_ctx *vcpus, int nvcpu);

/**
 * vm_preserve_luo() - Suspend VM and preserve state across live update.
 * @ctx: Pointer to the KVM VM context.
 * @session_name: Name of the live update session to register.
 *
 * Return: 0 on success, negative error code on failure.
 */
int vm_preserve_luo(struct kvm_ctx *ctx, const char *session_name);

/**
 * vm_preserve_luo_strategy() - Preserve VM state using explicit strategy.
 * @ctx: Pointer to the KVM VM context.
 * @session_name: Name of the live update session to register.
 * @strategy: Optional strategy string (e.g. "cpu,vcpu", "vcpu", "cpu1,vcpu0").
 *
 * Return: 0 on success, negative error code on failure.
 */
int vm_preserve_luo_strategy(struct kvm_ctx *ctx, const char *session_name,
			     const char *strategy);

/**
 * vm_resume_luo() - Probe and resume guest from preserved LUO session.
 * @opts: VMM configuration options.
 * @ctx: Pointer to the KVM VM context to populate.
 *
 * Return: 0 if session resumed, negative error code if no session found.
 */
int vm_resume_luo(struct vmm_opts *opts, struct kvm_ctx *ctx);

/**
 * vm_teardown() - Release VM resources, close descriptors, and unmap memory.
 * @ctx: Pointer to the KVM VM context.
 */
void vm_teardown(struct kvm_ctx *ctx);

/**
 * vm_arch_init() - Perform arch-specific VM setup and memory mapping.
 * @opts: VMM configuration options.
 * @ctx: Pointer to the KVM VM context.
 */
void vm_arch_init(struct vmm_opts *opts, struct kvm_ctx *ctx);

/**
 * vm_arch_post_init() - Perform post-vCPU arch device initialization.
 * @opts: VMM configuration options.
 * @ctx: Pointer to the KVM VM context.
 *
 * Called after all vCPU file descriptors have been created.
 */
void vm_arch_post_init(struct vmm_opts *opts, struct kvm_ctx *ctx);

/**
 * vcpu_arch_init() - Perform arch-specific vCPU register and CPUID setup.
 * @opts: VMM configuration options.
 * @vcpu: Pointer to the vCPU context to initialize.
 */
void vcpu_arch_init(struct vmm_opts *opts, struct vcpu_ctx *vcpu);

/**
 * handle_arch_exit() - Handle architecture-specific KVM exit reason.
 * @vcpu: Pointer to the vCPU context that exited.
 */
void handle_arch_exit(struct vcpu_ctx *vcpu);

/**
 * uart_irq_pulse() - Set virtual UART interrupt line level.
 * @ctx: Pointer to the KVM VM context.
 * @level: Interrupt line level (1 for assert, 0 for deassert).
 */
void uart_irq_pulse(struct kvm_ctx *ctx, int level);

/**
 * vm_arch_teardown() - Perform arch-specific teardown and close descriptors.
 * @ctx: Pointer to the KVM VM context.
 */
void vm_arch_teardown(struct kvm_ctx *ctx);

#define CONSOLE_RX_BUF_SIZE	1024

/**
 * console_rx_push() - Push a byte into the console RX ring buffer.
 * @c: Byte to push.
 *
 * Return: 0 on success, -1 if buffer full.
 */
int console_rx_push(uint8_t c);

/**
 * console_rx_pop() - Pop a byte from the console RX ring buffer.
 * @c: Pointer to store popped byte.
 *
 * Return: 0 on success, -1 if buffer empty.
 */
int console_rx_pop(uint8_t *c);

/**
 * console_rx_has_data() - Check if console RX buffer contains data.
 *
 * Return: 1 if data is available, 0 otherwise.
 */
int console_rx_has_data(void);

/**
 * vm_arch_uart_rx() - Notify architecture backend of pending UART RX input.
 * @ctx: Pointer to KVM VM context.
 */
void vm_arch_uart_rx(struct kvm_ctx *ctx);

#endif
