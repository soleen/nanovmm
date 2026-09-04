#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/signalfd.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#include "nvmm.h"

static atomic_bool g_vm_running = true;
static atomic_bool vm_is_paused = false;
static atomic_int paused_vcpus_count = 0;
static pthread_mutex_t pause_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t pause_cond = PTHREAD_COND_INITIALIZER;
static volatile int g_vm_preserved = 0;
static int g_preserve_sess_fd = -1;

static uint8_t console_rx_buf[CONSOLE_RX_BUF_SIZE];
static size_t console_rx_head = 0;
static size_t console_rx_tail = 0;
static pthread_mutex_t console_rx_lock = PTHREAD_MUTEX_INITIALIZER;

static struct termios orig_termios;
static int orig_stdin_flags = -1;
static bool termios_raw = false;

static struct kvm_ctx *g_global_ctx = NULL;
static const char *g_session_name = NULL;

/*
 * LUO session fds kept open until first successful vCPU execution,
 * guaranteeing rollback safety if resume fails immediately.
 */
static int g_luo_sess_fd = -1;
static int g_luo_fd = -1;
static volatile int g_luo_finalized = 0;
static void finish_luo_session(int finalize);

int console_rx_push(uint8_t c)
{
	int ret = -1;

	pthread_mutex_lock(&console_rx_lock);
	size_t next = (console_rx_head + 1) % CONSOLE_RX_BUF_SIZE;
	if (next != console_rx_tail) {
		console_rx_buf[console_rx_head] = c;
		console_rx_head = next;
		ret = 0;
	}
	pthread_mutex_unlock(&console_rx_lock);
	return ret;
}

int console_rx_pop(uint8_t *c)
{
	int ret = -1;

	pthread_mutex_lock(&console_rx_lock);
	if (console_rx_tail != console_rx_head) {
		*c = console_rx_buf[console_rx_tail];
		console_rx_tail = (console_rx_tail + 1) % CONSOLE_RX_BUF_SIZE;
		ret = 0;
	}
	pthread_mutex_unlock(&console_rx_lock);
	return ret;
}

int console_rx_has_data(void)
{
	int ret;

	pthread_mutex_lock(&console_rx_lock);
	ret = (console_rx_tail != console_rx_head);
	pthread_mutex_unlock(&console_rx_lock);
	return ret;
}

static void termios_restore(void)
{
	if (termios_raw) {
		tcsetattr(STDIN_FILENO, TCSAFLUSH, &orig_termios);
		if (orig_stdin_flags >= 0)
			fcntl(STDIN_FILENO, F_SETFL, orig_stdin_flags);
		termios_raw = false;
	}
}

static void termios_setup_raw(void)
{
	if (!isatty(STDIN_FILENO))
		return;

	if (tcgetattr(STDIN_FILENO, &orig_termios) < 0)
		return;

	orig_stdin_flags = fcntl(STDIN_FILENO, F_GETFL, 0);
	if (orig_stdin_flags >= 0)
		fcntl(STDIN_FILENO, F_SETFL, orig_stdin_flags | O_NONBLOCK);

	struct termios raw = orig_termios;
	cfmakeraw(&raw);
	if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw) == 0) {
		termios_raw = true;
		atexit(termios_restore);
	}
}

/**
 * sigusr1_handler() - Signal handler to interrupt KVM_RUN with EINTR.
 * @sig: Signal number received.
 */
static void sigusr1_handler(int sig __maybe_unused)
{
}

/**
 * die() - Print error message with errno and terminate execution.
 * @msg: Error description prefix.
 */
void die(const char *msg)
{
	int err = errno;

	errno = err;
	perror(msg);
	exit(1);
}

/**
 * pulse_irq() - Assert and deassert an interrupt line on the VM.
 * @ctx: Pointer to KVM VM context.
 * @irq: Interrupt line number to pulse.
 */
void pulse_irq(struct kvm_ctx *ctx, int irq)
{
	struct kvm_irq_level level;
	level.irq = irq;
	level.level = 1;
	ioctl(ctx->vm_fd, KVM_IRQ_LINE, &level);
	level.level = 0;
	ioctl(ctx->vm_fd, KVM_IRQ_LINE, &level);
}

/**
 * vm_suspend() - Pause all vCPU threads.
 * @ctx: Pointer to KVM VM context.
 * @vcpus: Array of vCPU contexts.
 * @nvcpu: Number of vCPUs.
 */
void vm_suspend(struct kvm_ctx *ctx __maybe_unused,
		struct vcpu_ctx *vcpus, int nvcpu)
{
	pthread_t self = pthread_self();
	int calling_vcpu = -1;
	int initial_paused = 0;
	int i;

	if (atomic_load(&vm_is_paused)) {
		printf("\r\n[NVMM] VM is already suspended.\r\n");
		return;
	}

	for (i = 0; i < nvcpu; i++) {
		if (pthread_equal(self, vcpus[i].tid)) {
			calling_vcpu = i;
			break;
		}
	}

	if (calling_vcpu >= 0)
		initial_paused = 1;

	printf("\r\n[NVMM] Suspending VM and pausing vCPU threads...\r\n");
	atomic_store(&paused_vcpus_count, initial_paused);
	atomic_store(&vm_is_paused, true);

	for (i = 0; i < nvcpu; i++) {
		if (i == calling_vcpu)
			continue;
		if (pthread_kill(vcpus[i].tid, 0) != 0) {
			atomic_fetch_add(&paused_vcpus_count, 1);
			continue;
		}
		if (vcpus[i].run)
			vcpus[i].run->immediate_exit = 1;
		pthread_kill(vcpus[i].tid, SIGUSR1);
	}

	/* Wait for all vCPUs to pause */
	while (atomic_load(&paused_vcpus_count) < nvcpu) {
		for (i = 0; i < nvcpu; i++) {
			if (i == calling_vcpu)
				continue;
			if (vcpus[i].run)
				vcpus[i].run->immediate_exit = 1;
			if (pthread_kill(vcpus[i].tid, 0) == 0)
				pthread_kill(vcpus[i].tid, SIGUSR1);
		}
		usleep(5000);
	}

	printf("[NVMM] VM suspended. vCPU execution paused.\r\n");
}

/**
 * vm_resume() - Resume vCPU execution.
 * @ctx: Pointer to KVM VM context.
 * @vcpus: Array of vCPU contexts.
 * @nvcpu: Number of vCPUs.
 */
void vm_resume(struct kvm_ctx *ctx __maybe_unused,
	       struct vcpu_ctx *vcpus, int nvcpu)
{
	int i;

	if (!atomic_load(&vm_is_paused))
		return;

	printf("\r\n[NVMM] Resuming VM execution...\r\n");

	for (i = 0; i < nvcpu; i++) {
		if (vcpus[i].run)
			vcpus[i].run->immediate_exit = 0;
#ifdef KVM_SET_MP_STATE
		struct kvm_mp_state mp = { .mp_state = KVM_MP_STATE_RUNNABLE };
		ioctl(vcpus[i].vcpu_fd, KVM_SET_MP_STATE, &mp);
#endif
	}

	atomic_store(&paused_vcpus_count, 0);
	atomic_store(&vm_is_paused, false);

	pthread_mutex_lock(&pause_mutex);
	pthread_cond_broadcast(&pause_cond);
	pthread_mutex_unlock(&pause_mutex);
}

static int preserve_fd(int sess_fd, int fd, uint64_t token, const char *name)
{
	struct liveupdate_session_preserve_fd pfd;

	memset(&pfd, 0, sizeof(pfd));
	pfd.size = sizeof(pfd);
	pfd.fd = fd;
	pfd.token = token;
	if (ioctl(sess_fd, LIVEUPDATE_SESSION_PRESERVE_FD, &pfd) < 0) {
		perror(name);
		return -1;
	}
	return 0;
}

static int retrieve_fd(int sess_fd, uint64_t token, const char *name)
{
	struct liveupdate_session_retrieve_fd rfd;

	memset(&rfd, 0, sizeof(rfd));
	rfd.size = sizeof(rfd);
	rfd.token = token;
	if (ioctl(sess_fd, LIVEUPDATE_SESSION_RETRIEVE_FD, &rfd) < 0) {
		if (name)
			perror(name);
		return -1;
	}
	return rfd.fd;
}

static int preserve_single_pcpu(struct kvm_ctx *ctx, int sess_fd, int target_pcpu)
{
	char path[128], desc[64];

	if (target_pcpu < 0 || target_pcpu >= NVMM_MAX_PCPUS)
		return -1;

	if (ctx->pcpu_preserve_fds[target_pcpu] >= 0)
		return 0; /* Already preserved */

	snprintf(path, sizeof(path), "/sys/devices/system/cpu/cpu%d/preserve", target_pcpu);
	ctx->pcpu_preserve_fds[target_pcpu] = open(path, O_RDWR);
	if (ctx->pcpu_preserve_fds[target_pcpu] < 0)
		ctx->pcpu_preserve_fds[target_pcpu] = open(path, O_RDONLY);

	if (ctx->pcpu_preserve_fds[target_pcpu] < 0) {
		fprintf(stderr, "[NVMM LUO ERROR] Failed to open %s: %s\r\n",
			path, strerror(errno));
		return -1;
	}

	snprintf(desc, sizeof(desc), "LIVEUPDATE_SESSION_PRESERVE_FD (CPU %d)", target_pcpu);
	if (preserve_fd(sess_fd, ctx->pcpu_preserve_fds[target_pcpu],
			LUO_CPU_BASE_TOKEN + target_pcpu, desc) < 0)
		return -1;
	printf("[NVMM LUO] Preserved physical host CPU %d (token 0x%llx)\r\n",
	       target_pcpu, (unsigned long long)(LUO_CPU_BASE_TOKEN + target_pcpu));
	return 0;
}

static int preserve_single_vcpu(struct kvm_ctx *ctx, int sess_fd, int vcpu_id)
{
	char desc[64];

	if (vcpu_id < 0 || vcpu_id >= ctx->nvcpu)
		return -1;

	snprintf(desc, sizeof(desc), "LIVEUPDATE_SESSION_PRESERVE_FD (vCPU %d)", vcpu_id);
	if (preserve_fd(sess_fd, ctx->vcpus[vcpu_id].vcpu_fd,
			LUO_VCPU_BASE_TOKEN + vcpu_id, desc) < 0)
		return -1;

	printf("[NVMM LUO] Preserved guest vCPU %d FD (token 0x%llx)\r\n",
	       vcpu_id, (unsigned long long)(LUO_VCPU_BASE_TOKEN + vcpu_id));
	return 0;
}

struct suspend_strategy_config {
	cpu_set_t pcpus_set;
	bool preserve_pcpus;
};

static int parse_id_range(const char *str, int *start, int *end)
{
	const char *dash;

	*start = atoi(str);
	dash = strchr(str, '-');
	if (dash)
		*end = atoi(dash + 1);
	else
		*end = *start;

	return (*start >= 0 && *end >= *start) ? 0 : -1;
}

static int parse_strategy_token(struct kvm_ctx *ctx, const char *token,
				struct suspend_strategy_config *cfg)
{
	int start, end, i;
	const char *p = token;

	if (strcmp(token, "default") == 0 || strcmp(token, "ram") == 0) {
		cfg->preserve_pcpus = false;
		return 0;
	}

	if (strncmp(p, "cpu", 3) == 0)
		p += 3;

	if (*p >= '0' && *p <= '9') {
		cfg->preserve_pcpus = true;
		if (parse_id_range(p, &start, &end) < 0)
			return -1;
		for (i = start; i <= end && i < NVMM_MAX_PCPUS; i++)
			CPU_SET(i, &cfg->pcpus_set);
		return 0;
	}

	fprintf(stderr, "[NVMM LUO WARNING] Unknown suspend strategy token: '%s'\r\n", token);
	return -1;
}

static int parse_suspend_strategy(struct kvm_ctx *ctx, const char *strategy,
				  struct suspend_strategy_config *cfg)
{
	char strat_copy[256];
	char *token, *saveptr = NULL;

	memset(cfg, 0, sizeof(*cfg));
	CPU_ZERO(&cfg->pcpus_set);

	if (!strategy || *strategy == '\0')
		return 0;

	strncpy(strat_copy, strategy, sizeof(strat_copy) - 1);
	strat_copy[sizeof(strat_copy) - 1] = '\0';

	token = strtok_r(strat_copy, ", ", &saveptr);
	while (token) {
		if (parse_strategy_token(ctx, token, cfg) < 0)
			return -1;
		token = strtok_r(NULL, ", ", &saveptr);
	}

	return 0;
}

static int open_luo_device(void)
{
	int fd = open(LUO_DEVICE_PATH, O_RDWR);
	if (fd < 0 && errno == ENOENT)
		fd = open("/mnt/devtmpfs/liveupdate", O_RDWR);
	return fd;
}

/**
 * vm_preserve_luo_strategy() - Suspend VM and preserve state using explicit strategy.
 * @ctx: Pointer to KVM VM context.
 * @session_name: Name of the live update session to register.
 * @strategy: Optional comma-delimited strategy tokens (or NULL for default).
 *
 * Return: 0 on success, negative error code on failure.
 */

int vm_preserve_luo_strategy(struct kvm_ctx *ctx, const char *session_name,
			     const char *strategy)
{
	struct liveupdate_ioctl_create_session cs;
	struct suspend_strategy_config cfg;
	struct nvmm_machine_state *state = NULL;
	int luo_fd = -1, sess_fd = -1, state_fd = -1;
	struct timespec ts;
	int i;

	if (!session_name) {
		fprintf(stderr,
			"[NVMM LUO ERROR] Cannot preserve VM: No session "
			"name provided via -s <name> at launch\r\n");
		return -1;
	}

	if (g_vm_preserved) {
		printf("[NVMM LUO] VM is already preserved in session '%s'.\r\n",
		       session_name);
		int pfd = open("/tmp/nvmm_preserved", O_CREAT | O_WRONLY | O_TRUNC, 0644);
		if (pfd >= 0)
			close(pfd);
		return 0;
	}

	/* Parse and validate suspend strategy before proceeding */
	if (parse_suspend_strategy(ctx, strategy, &cfg) < 0)
		return -1;

	if (cfg.preserve_pcpus) {
		int has_caretaker = ioctl(ctx->kvm_fd, KVM_CHECK_EXTENSION, KVM_CAP_CARETAKER);
		if (has_caretaker <= 0) {
			fprintf(stderr,
				"[NVMM LUO WARNING] KVM_CAP_CARETAKER not supported on host; "
				"falling back to RAM preservation (vCPU only).\r\n");
			cfg.preserve_pcpus = false;
		}
	}

	ctx->orphan_mode = cfg.preserve_pcpus;

	/* 1. Suspend VM and pause vCPU threads */
	vm_suspend(ctx, ctx->vcpus, ctx->nvcpu);
	g_vm_preserved = 1;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	ctx->pre_suspend_time_ns = (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;

	/* Close any previous session before opening new one */
	finish_luo_session(1);

	/* 2. Open /dev/liveupdate device */
	luo_fd = open_luo_device();
	if (luo_fd < 0) {
		if (errno == ENOENT) {
			fprintf(stderr,
				"[NVMM LUO WARNING] " LUO_DEVICE_PATH
				" is not present, ignoring\n");
		} else {
			perror("open " LUO_DEVICE_PATH);
		}
		goto err_resume;
	}

	/* 3. Create LUO session */
	memset(&cs, 0, sizeof(cs));
	cs.size = sizeof(cs);
	strncpy((char *)cs.name, session_name, sizeof(cs.name) - 1);
	if (ioctl(luo_fd, LIVEUPDATE_IOCTL_CREATE_SESSION, &cs) < 0) {
		perror("LIVEUPDATE_IOCTL_CREATE_SESSION");
		goto err_close;
	}
	sess_fd = cs.fd;

	/* 4. Preserve KVM VM and Guest RAM file descriptors */
	if (preserve_fd(sess_fd, ctx->vm_fd, LUO_VM_TOKEN,
			"LIVEUPDATE_SESSION_PRESERVE_FD (VM)") < 0)
		goto err_close;

	if (preserve_fd(sess_fd, ctx->ram_fd, LUO_RAM_TOKEN,
			"LIVEUPDATE_SESSION_PRESERVE_FD (RAM/GMEM)") < 0)
		goto err_close;

	/* 5. Dispatch physical CPU and vCPU preservation */
	if (cfg.preserve_pcpus) {
		for (i = 0; i < NVMM_MAX_PCPUS; i++) {
			if (!CPU_ISSET(i, &cfg.pcpus_set))
				continue;
			if (preserve_single_pcpu(ctx, sess_fd, i) < 0)
				goto err_close;
		}
	}

	for (i = 0; i < ctx->nvcpu; i++) {
		if (preserve_single_vcpu(ctx, sess_fd, i) < 0)
			goto err_close;
	}

	/* 6. Build and preserve unified Machine State memfd */
	state = calloc(1, sizeof(*state));
	if (!state)
		die("calloc state");

	state->magic = NVMM_STATE_MAGIC;
	state->version = NVMM_STATE_VERSION;
	state->mem_size = ctx->mem_size;
	state->nvcpu = ctx->nvcpu;
	state->state_size = sizeof(*state);
	if (ctx->orphan_mode)
		state->flags |= NVMM_STATE_FLAG_ORPHAN_CPU;

	clock_gettime(CLOCK_REALTIME, &ts);
	state->suspend_timestamp_ns = (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
	state->pre_suspend_time_ns = ctx->pre_suspend_time_ns;
	state->pre_suspend_seq = ctx->pre_suspend_seq;
	state->pre_suspend_hw_ts = ctx->pre_suspend_hw_ts;

	state_fd = memfd_create(LUO_STATE_NAME, 0);
	if (state_fd < 0)
		goto err_close;
	if (ftruncate(state_fd, sizeof(*state)) < 0)
		goto err_close;

	if (pwrite(state_fd, state, sizeof(*state), 0) != sizeof(*state))
		goto err_close;

	free(state);
	state = NULL;

	if (preserve_fd(sess_fd, state_fd, LUO_STATE_TOKEN,
			"LIVEUPDATE_SESSION_PRESERVE_FD (STATE)") < 0)
		goto err_close;

	close(state_fd);
	close(luo_fd);

	printf("\r\n[NVMM LUO] Preserved KVM VM, Guest RAM (guest_memfd), %d vCPU(s), and Machine State\r\n",
	       ctx->nvcpu);
	printf("[NVMM LUO] LUO Session '%s' successfully prepared and preserved. %s\r\n",
	       session_name,
	       ctx->orphan_mode ? "Continuing on-core execution." : "Suspended in RAM.");
	fflush(stdout);

	int pfd = open("/tmp/nvmm_preserved", O_CREAT | O_WRONLY | O_TRUNC, 0644);
	if (pfd >= 0)
		close(pfd);

	g_preserve_sess_fd = sess_fd;
	return 0;

err_close:
	if (state)
		free(state);
	if (state_fd >= 0)
		close(state_fd);
	if (sess_fd >= 0)
		close(sess_fd);
	if (luo_fd >= 0)
		close(luo_fd);
	for (i = 0; i < NVMM_MAX_PCPUS; i++) {
		if (ctx->pcpu_preserve_fds[i] >= 0) {
			close(ctx->pcpu_preserve_fds[i]);
			ctx->pcpu_preserve_fds[i] = -1;
		}
	}
	if (ctx->orphan_mode)
		ctx->orphan_mode = 0;

err_resume:
	g_vm_preserved = 0;
	fprintf(stderr, "[NVMM LUO] Preservation failed. Resuming VM...\r\n");
	vm_resume(ctx, ctx->vcpus, ctx->nvcpu);
	return -1;
}

/**
 * cancel_preservation() - Cancel preservation, restore physical CPUs, and resume VM.
 * @ctx: Pointer to KVM VM context.
 */
static void cancel_preservation(struct kvm_ctx *ctx)
{
	int i;

	if (!g_vm_preserved) {
		vm_resume(ctx, ctx->vcpus, ctx->nvcpu);
		return;
	}

	printf("\r\n[NVMM LUO] Cancelling preservation and restoring VM execution...\r\n");

	unlink("/tmp/nvmm_preserved");

	if (g_preserve_sess_fd >= 0) {
		close(g_preserve_sess_fd);
		g_preserve_sess_fd = -1;
	}

	g_vm_preserved = 0;
	g_luo_finalized = 0;

	for (i = 0; i < NVMM_MAX_PCPUS; i++) {
		if (ctx->pcpu_preserve_fds[i] >= 0) {
			close(ctx->pcpu_preserve_fds[i]);
			ctx->pcpu_preserve_fds[i] = -1;
		}
	}

	if (ctx->orphan_mode)
		ctx->orphan_mode = 0;

#ifdef KVM_SET_MP_STATE
	for (i = 0; i < ctx->nvcpu; i++) {
		struct kvm_mp_state mp = { .mp_state = KVM_MP_STATE_RUNNABLE };
		ioctl(ctx->vcpus[i].vcpu_fd, KVM_SET_MP_STATE, &mp);
	}
#endif

	vm_resume(ctx, ctx->vcpus, ctx->nvcpu);
	termios_setup_raw();
}

/**
 * vm_preserve_luo() - Suspend VM with default strategy.
 * @ctx: Pointer to KVM VM context.
 * @session_name: Name of live update session.
 *
 * Return: 0 on success, negative error code on failure.
 */
int vm_preserve_luo(struct kvm_ctx *ctx, const char *session_name)
{
	return vm_preserve_luo_strategy(ctx, session_name, NULL);
}

static void handle_system_event(struct vcpu_ctx *vcpu)
{
	switch (vcpu->run->system_event.type) {
	case KVM_SYSTEM_EVENT_SHUTDOWN:
		printf("\n[NVMM] Guest requested poweroff. Shutting down.\n");
		atomic_store(&g_vm_running, false);
		vm_teardown(vcpu->ctx);
		exit(0);
	case KVM_SYSTEM_EVENT_RESET:
		printf("\n[NVMM] Guest requested reset. Halting VM.\n");
		atomic_store(&g_vm_running, false);
		vm_teardown(vcpu->ctx);
		exit(0);
	case KVM_SYSTEM_EVENT_CRASH:
		printf("\n[NVMM] Guest crashed via PV-panic event.\n");
		atomic_store(&g_vm_running, false);
		vm_teardown(vcpu->ctx);
		exit(1);
		break;
	default:
		break;
	}
}

/**
 * vcpu_thread() - Execution thread running KVM_RUN loop for a vCPU.
 * @arg: Pointer to vCPU context.
 *
 * Return: Always NULL.
 */
static void *vcpu_thread(void *arg)
{
	struct vcpu_ctx *vcpu = arg;
	sigset_t sigmask;
	int ret;

	sigemptyset(&sigmask);
	sigaddset(&sigmask, SIGUSR1);
	pthread_sigmask(SIG_UNBLOCK, &sigmask, NULL);

	printf("VCPU %d: Thread started\n", vcpu->id);

	while (atomic_load(&g_vm_running)) {
		if (atomic_load(&vm_is_paused)) {
			atomic_fetch_add(&paused_vcpus_count, 1);
			printf("[NVMM] vCPU %d acknowledged pause (%d/%d)\r\n",
			       vcpu->id, atomic_load(&paused_vcpus_count), vcpu->ctx->nvcpu);
			fflush(stdout);

			pthread_mutex_lock(&pause_mutex);
			while (atomic_load(&vm_is_paused))
				pthread_cond_wait(&pause_cond, &pause_mutex);
			pthread_mutex_unlock(&pause_mutex);

			if (vcpu->run)
				vcpu->run->immediate_exit = 0;
		}

		ret = ioctl(vcpu->vcpu_fd, KVM_RUN, 0);
		if (ret < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			if (atomic_load(&vm_is_paused))
				continue;
			perror("KVM_RUN");
			exit(1);
		}

		switch (vcpu->run->exit_reason) {
		case KVM_EXIT_HLT:
			if (g_luo_sess_fd >= 0)
				finish_luo_session(1);
			break;
		case KVM_EXIT_FAIL_ENTRY: {
			uint64_t r = vcpu->run->fail_entry.hardware_entry_failure_reason;
			fprintf(stderr,
				"[NVMM FATAL] VCPU %d: KVM_EXIT_FAIL_ENTRY "
				"(reason: 0x%llx). Halting VM.\n",
				vcpu->id, (unsigned long long)r);
			exit(1);
		}
		case KVM_EXIT_INTERNAL_ERROR:
			fprintf(stderr,
				"[NVMM FATAL] VCPU %d: "
				"KVM_EXIT_INTERNAL_ERROR (suberror: 0x%x). "
				"Halting VM.\n",
				vcpu->id, vcpu->run->internal.suberror);
			exit(1);
		case KVM_EXIT_SYSTEM_EVENT:
			handle_system_event(vcpu);
			break;
		default:
			if (g_luo_sess_fd >= 0)
				finish_luo_session(1);
			handle_arch_exit(vcpu);
			break;
		}
	}
	return NULL;
}

static void handle_fifo_command(struct kvm_ctx *ctx, const char *cmd)
{
	if (strcmp(cmd, "resume") == 0) {
		printf("[NVMM FIFO] Resuming VM execution...\r\n");
		cancel_preservation(ctx);
	} else if (strncmp(cmd, "suspend", 7) == 0) {
		const char *strat = cmd + 7;
		while (*strat == ' ' || *strat == '\t')
			strat++;
		if (*strat == '\0')
			strat = NULL;
		printf("[NVMM FIFO] Preserving VM%s%s%s...\r\n",
		       strat ? " (cpus: " : "",
		       strat ? strat : "",
		       strat ? ")" : "");
		vm_preserve_luo_strategy(ctx, g_session_name, strat);
	} else if (strcmp(cmd, "quit") == 0) {
		printf("[NVMM FIFO] Shutting down VM...\r\n");
		atomic_store(&g_vm_running, false);
	} else {
		fprintf(stderr, "[NVMM FIFO WARNING] Unknown command: '%s'\r\n", cmd);
	}
}

static void control_loop(struct kvm_ctx *ctx)
{
	struct pollfd pfds[3];
	char buf[256];
	int sfd;
	sigset_t mask;
	int nfds = 2;
	bool escape_seen = false;

	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);
	sigaddset(&mask, SIGUSR2);
	pthread_sigmask(SIG_BLOCK, &mask, NULL);

	sfd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
	if (sfd < 0)
		die("signalfd");

	pfds[0].fd = ctx->fifo_fd;
	pfds[0].events = POLLIN;
	pfds[1].fd = sfd;
	pfds[1].events = POLLIN;
	pfds[2].fd = STDIN_FILENO;
	pfds[2].events = POLLIN;
	nfds = 3;

	while (atomic_load(&g_vm_running)) {
		pfds[0].revents = 0;
		pfds[1].revents = 0;
		if (nfds > 2)
			pfds[2].revents = 0;
		int ret = poll(pfds, nfds, 500);
		if (ret < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			break;
		}

		if (pfds[1].revents & POLLIN) {
			struct signalfd_siginfo fdsi;
			ssize_t s = read(sfd, &fdsi, sizeof(fdsi));
			if (s == sizeof(fdsi)) {
				if (fdsi.ssi_signo == SIGUSR2) {
					printf("\r\n[NVMM] Received SIGUSR2: preserving VM...\r\n");
					termios_restore();
					vm_preserve_luo(ctx, g_session_name);
				} else if (fdsi.ssi_signo == SIGINT || fdsi.ssi_signo == SIGTERM) {
					if (g_vm_preserved) {
						printf("\r\n[NVMM] Ignoring signal %d (VM preserved for live update)\r\n",
						       fdsi.ssi_signo);
						continue;
					}
					printf("\r\n[NVMM] Terminating VM on signal %d...\r\n", fdsi.ssi_signo);
					atomic_store(&g_vm_running, false);
					break;
				}
			}
		}

		if (pfds[0].revents & POLLIN) {
			ssize_t n = read(ctx->fifo_fd, buf, sizeof(buf) - 1);
			if (n > 0) {
				buf[n] = '\0';
				char *line = buf;
				while (line && *line) {
					char *next = strchr(line, '\n');
					if (next) {
						*next = '\0';
						next++;
					}
					size_t len = strlen(line);
					while (len > 0 && (line[len - 1] == '\r' || line[len - 1] == ' ' || line[len - 1] == '\t'))
						line[--len] = '\0';

					while (*line == ' ' || *line == '\t')
						line++;

					if (*line)
						handle_fifo_command(ctx, line);
					line = next;
				}
			}
		}

		if (nfds > 2 && pfds[2].fd >= 0 && (pfds[2].revents & POLLIN)) {
			uint8_t in_buf[64];
			ssize_t n = read(STDIN_FILENO, in_buf, sizeof(in_buf));
			if (n > 0) {
				int pushed = 0;
				for (ssize_t i = 0; i < n; i++) {
					uint8_t c = in_buf[i];

					if (escape_seen) {
						escape_seen = false;
						if (c == 'x' || c == 'X' || c == 0x18) {
							printf("\r\n[NVMM] Terminating VM on console escape (Ctrl-A x)...\r\n");
							atomic_store(&g_vm_running, false);
							break;
						}
						if (c == 0x01 || c == 'a' || c == 'A') {
							if (console_rx_push(0x01) == 0)
								pushed++;
						} else {
							if (console_rx_push(0x01) == 0)
								pushed++;
							if (console_rx_push(c) == 0)
								pushed++;
						}
						continue;
					}

					if (c == 0x01) { /* Ctrl-A escape prefix */
						escape_seen = true;
						continue;
					}

					if (c == 0x1d) { /* Ctrl-] escape */
						printf("\r\n[NVMM] Terminating VM on console escape (Ctrl-])...\r\n");
						atomic_store(&g_vm_running, false);
						break;
					}

					if (console_rx_push(c) == 0)
						pushed++;
				}
				if (!atomic_load(&g_vm_running))
					break;
				if (pushed > 0)
					vm_arch_uart_rx(ctx);
			} else if (n == 0 || (n < 0 && errno != EAGAIN && errno != EINTR)) {
				pfds[2].fd = -1;
			}
		} else if (nfds > 2 && pfds[2].fd >= 0 && (pfds[2].revents & (POLLHUP | POLLERR | POLLNVAL))) {
			pfds[2].fd = -1;
		}
	}

	close(sfd);
}

/**
 * init_control_fifo() - Initialize signal masks and runtime control FIFO.
 * @ctx: Pointer to KVM VM context.
 * @opts: Pointer to VMM configuration options.
 */
static void init_control_fifo(struct kvm_ctx *ctx, struct vmm_opts *opts)
{
	struct sigaction sa;
	sigset_t mask;

	g_global_ctx = ctx;
	if (opts->session_name)
		g_session_name = opts->session_name;

	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);
	sigaddset(&mask, SIGUSR2);
	pthread_sigmask(SIG_BLOCK, &mask, NULL);

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sigusr1_handler;
	sigaction(SIGUSR1, &sa, NULL);

	if (ctx->fifo_fd >= 0)
		return;

	if (opts->fifo_path && *opts->fifo_path)
		snprintf(ctx->fifo_path, sizeof(ctx->fifo_path), "%s",
			 opts->fifo_path);
	else
		snprintf(ctx->fifo_path, sizeof(ctx->fifo_path),
			 "/tmp/nvmm_%s.fifo",
			 g_session_name ? g_session_name : "default");

	unlink(ctx->fifo_path);
	mkfifo(ctx->fifo_path, 0666);
	ctx->fifo_fd = open(ctx->fifo_path, O_RDWR | O_NONBLOCK);
}

/**
 * start_vm_threads() - Launch POSIX threads for vCPUs and control loop.
 * @ctx: Pointer to KVM VM context.
 * @opts: Pointer to VMM configuration options.
 */
static void start_vm_threads(struct kvm_ctx *ctx, struct vmm_opts *opts)
{
	int i;

	init_control_fifo(ctx, opts);

	atomic_store(&g_vm_running, true);

	for (i = 0; i < ctx->nvcpu; i++)
		pthread_create(&ctx->vcpus[i].tid, NULL, vcpu_thread, &ctx->vcpus[i]);

	termios_setup_raw();
	control_loop(ctx);
	termios_restore();

	for (i = 0; i < ctx->nvcpu; i++) {
		if (ctx->vcpus[i].run)
			ctx->vcpus[i].run->immediate_exit = 1;
		if (ctx->vcpus[i].tid)
			pthread_kill(ctx->vcpus[i].tid, SIGUSR1);
	}

	for (i = 0; i < ctx->nvcpu; i++) {
		if (ctx->vcpus[i].tid)
			pthread_join(ctx->vcpus[i].tid, NULL);
	}
}

static void create_kvm_vm(struct kvm_ctx *ctx)
{
	ctx->kvm_fd = open(KVM_DEVICE_PATH, O_RDWR);
	if (ctx->kvm_fd < 0)
		die("open " KVM_DEVICE_PATH);

	ctx->vm_fd = ioctl(ctx->kvm_fd, KVM_CREATE_VM, 0);
	if (ctx->vm_fd < 0)
		die("KVM_CREATE_VM");
}

static void setup_vcpus(struct vmm_opts *opts, struct kvm_ctx *ctx,
			int sess_fd)
{
	int mmap_size, i;

	mmap_size = ioctl(ctx->kvm_fd, KVM_GET_VCPU_MMAP_SIZE, 0);
	if (mmap_size <= 0)
		die("KVM_GET_VCPU_MMAP_SIZE");
	ctx->vcpu_mmap_size = mmap_size;

	ctx->vcpus = calloc(opts->nvcpu, sizeof(struct vcpu_ctx));
	if (!ctx->vcpus)
		die("calloc vcpus");
	ctx->nvcpu = opts->nvcpu;

	for (i = 0; i < opts->nvcpu; i++) {
		ctx->vcpus[i].ctx = ctx;
		ctx->vcpus[i].id = i;

		if (opts->is_resume && sess_fd >= 0) {
			char desc[64];

			snprintf(desc, sizeof(desc), "RETRIEVE_VCPU_%d", i);
			ctx->vcpus[i].vcpu_fd = retrieve_fd(sess_fd,
							    LUO_VCPU_BASE_TOKEN + i,
							    desc);
			if (ctx->vcpus[i].vcpu_fd < 0)
				die("retrieve vcpu");
		} else {
			ctx->vcpus[i].vcpu_fd = ioctl(ctx->vm_fd, KVM_CREATE_VCPU,
						     (unsigned long)i);
			if (ctx->vcpus[i].vcpu_fd < 0)
				die("KVM_CREATE_VCPU");
		}

		ctx->vcpus[i].run = mmap(NULL, mmap_size,
					 PROT_READ | PROT_WRITE,
					 MAP_SHARED,
					 ctx->vcpus[i].vcpu_fd, 0);
		if (ctx->vcpus[i].run == MAP_FAILED)
			die("mmap vcpu run");

		if (opts->is_resume) {
			if (ctx->vcpus[i].run)
				ctx->vcpus[i].run->immediate_exit = 0;
#ifdef KVM_SET_MP_STATE
			struct kvm_mp_state mp = { .mp_state = KVM_MP_STATE_RUNNABLE };
			ioctl(ctx->vcpus[i].vcpu_fd, KVM_SET_MP_STATE, &mp);
#endif
		}

		vcpu_arch_init(opts, &ctx->vcpus[i]);
	}

	vm_arch_post_init(opts, ctx);
}

static inline int map_guest_ram(struct kvm_ctx *ctx, size_t size)
{
	ctx->mem_size = size;
	ctx->mem = mmap(NULL, size, PROT_READ | PROT_WRITE,
			MAP_SHARED | MAP_POPULATE, ctx->ram_fd, 0);
	if (ctx->mem == MAP_FAILED)
		return -1;
#ifdef MADV_POPULATE_WRITE
	madvise(ctx->mem, size, MADV_POPULATE_WRITE);
#endif
	return 0;
}

static void run_vm(struct vmm_opts *opts, struct kvm_ctx *ctx)
{
	start_vm_threads(ctx, opts);
	vm_teardown(ctx);
}

/**
 * vm_resume_luo() - Resume VM state from a preserved LUO session.
 * @opts: Pointer to VMM configuration options.
 * @ctx: Pointer to KVM VM context to populate.
 *
 * Return: 0 on success, negative error code on failure.
 */
int vm_resume_luo(struct vmm_opts *opts, struct kvm_ctx *ctx)
{
	int luo_fd = -1, sess_fd = -1, state_fd = -1;
	struct liveupdate_ioctl_retrieve_session rs;
	struct nvmm_machine_state *state = NULL;
	const char *session_name = opts->session_name;
	int i;

	if (!session_name)
		return -1;

	memset(ctx, 0, sizeof(*ctx));
	for (i = 0; i < NVMM_MAX_PCPUS; i++)
		ctx->pcpu_preserve_fds[i] = -1;
	ctx->fifo_fd = -1;
	luo_fd = open_luo_device();
	if (luo_fd < 0) {
		if (errno == ENOENT) {
			fprintf(stderr,
				"[NVMM LUO WARNING] " LUO_DEVICE_PATH
				" is not present, ignoring\n");
		} else {
			perror("[NVMM LUO ERROR] open " LUO_DEVICE_PATH);
		}
		return -1;
	}

	memset(&rs, 0, sizeof(rs));
	rs.size = sizeof(rs);
	strncpy((char *)rs.name, session_name, sizeof(rs.name) - 1);
	if (ioctl(luo_fd, LIVEUPDATE_IOCTL_RETRIEVE_SESSION, &rs) < 0) {
		perror("[NVMM LUO ERROR] ioctl LIVEUPDATE_IOCTL_RETRIEVE_SESSION");
		close(luo_fd);
		return -1;
	}
	sess_fd = rs.fd;
	opts->is_resume = 1;
	init_control_fifo(ctx, opts);

	printf("[NVMM LUO] Found preserved LUO session '%s'. "
	       "Auto-resuming guest VM...\r\n", session_name);

	/* Retrieve KVM VM, RAM (guest_memfd), and Machine State memfds */
	ctx->vm_fd = retrieve_fd(sess_fd, LUO_VM_TOKEN, "RETRIEVE_VM");
	ctx->ram_fd = retrieve_fd(sess_fd, LUO_RAM_TOKEN, "RETRIEVE_RAM");
	state_fd = retrieve_fd(sess_fd, LUO_STATE_TOKEN, "RETRIEVE_STATE");
	if (ctx->vm_fd < 0 || ctx->ram_fd < 0 || state_fd < 0)
		goto err_out;

	for (i = 0; i < NVMM_MAX_PCPUS; i++) {
		int cpu_pfd = retrieve_fd(sess_fd,
					  LUO_CPU_BASE_TOKEN + i,
					  NULL);
		if (cpu_pfd >= 0)
			close(cpu_pfd);
	}

	ctx->kvm_fd = open(KVM_DEVICE_PATH, O_RDWR);
	if (ctx->kvm_fd < 0)
		die("open " KVM_DEVICE_PATH);

	state = malloc(sizeof(*state));
	if (!state)
		die("malloc state");

	if (pread(state_fd, state, sizeof(*state), 0) != sizeof(*state))
		die("pread state_fd");
	close(state_fd);
	state_fd = -1;

	if (state->magic != NVMM_STATE_MAGIC ||
	    state->version != NVMM_STATE_VERSION)
		die("Invalid NVMM machine state magic or version");
	if (state->state_size != sizeof(*state))
		die("NVMM machine state size mismatch: recompile nvmm");

	opts->mem_size = state->mem_size;
	opts->nvcpu = state->nvcpu;
	if (state->flags & NVMM_STATE_FLAG_ORPHAN_CPU)
		ctx->orphan_mode = 1;
	printf("[NVMM LUO] Retrieved Machine State (mem_size: %zu, "
	       "nvcpu: %d%s)\r\n", opts->mem_size, opts->nvcpu,
	       ctx->orphan_mode ? ", orphan mode" : "");

	ctx->pre_suspend_time_ns = state->pre_suspend_time_ns;
	ctx->pre_suspend_seq = state->pre_suspend_seq;
	ctx->pre_suspend_hw_ts = state->pre_suspend_hw_ts;

	if (state->suspend_timestamp_ns > 0) {
		struct timespec now;
		clock_gettime(CLOCK_REALTIME, &now);
		uint64_t now_ns = (uint64_t)now.tv_sec * 1000000000ULL +
				  now.tv_nsec;
		if (now_ns > state->suspend_timestamp_ns) {
			ctx->transition_ns = now_ns - state->suspend_timestamp_ns;
			uint64_t diff_ms = ctx->transition_ns / 1000000ULL;
			printf("[NVMM LUO] Host transition duration: "
			       "%llu ms\r\n",
			       (unsigned long long)diff_ms);
		}
	}

	/* mmap preserved RAM */
	if (map_guest_ram(ctx, opts->mem_size) < 0) {
		perror("mmap preserved RAM");
		goto err_out;
	}

	vm_arch_init(opts, ctx);

	/* Setup vCPUs */
	setup_vcpus(opts, ctx, sess_fd);
	free(state);
	state = NULL;

	g_luo_sess_fd = sess_fd;
	g_luo_fd = luo_fd;
	g_luo_finalized = 0;
	if (ctx->orphan_mode) {
		finish_luo_session(1);
	}

	run_vm(opts, ctx);

	if (__sync_bool_compare_and_swap(&g_luo_finalized, 0, 1)) {
		if (g_luo_sess_fd >= 0) {
			close(g_luo_sess_fd);
			g_luo_sess_fd = -1;
		}
		if (g_luo_fd >= 0) {
			close(g_luo_fd);
			g_luo_fd = -1;
		}
	}

	return 0;

err_out:
	if (ctx->fifo_fd >= 0) {
		close(ctx->fifo_fd);
		ctx->fifo_fd = -1;
		unlink(ctx->fifo_path);
	}
	if (state)
		free(state);
	if (state_fd >= 0)
		close(state_fd);
	if (sess_fd >= 0)
		close(sess_fd);
	if (luo_fd >= 0)
		close(luo_fd);
	return -1;
}

static void finish_luo_session(int finalize)
{
	printf("[NVMM LUO] finish_luo_session(finalize=%d) called, g_luo_sess_fd=%d\n",
	       finalize, g_luo_sess_fd);
	if (!__sync_bool_compare_and_swap(&g_luo_finalized, 0, 1)) {
		printf("[NVMM LUO] finish_luo_session already finalized!\n");
		return;
	}

	if (g_luo_sess_fd >= 0) {
		if (finalize) {
			struct liveupdate_session_finish fin;

			memset(&fin, 0, sizeof(fin));
			fin.size = sizeof(fin);
			printf("[NVMM LUO] Invoking ioctl(LIVEUPDATE_SESSION_FINISH)...\n");
			int ret = ioctl(g_luo_sess_fd, LIVEUPDATE_SESSION_FINISH, &fin);
			if (ret < 0)
				perror("[NVMM LUO] LIVEUPDATE_SESSION_FINISH");
			else
				printf("[NVMM LUO] LIVEUPDATE_SESSION_FINISH returned success (0)\n");
		}
		close(g_luo_sess_fd);
		g_luo_sess_fd = -1;
	}
	if (g_luo_fd >= 0) {
		close(g_luo_fd);
		g_luo_fd = -1;
	}
}

/**
 * vm_teardown() - Release VM resources, close descriptors, and unmap memory.
 * @ctx: Pointer to KVM VM context.
 */
void vm_teardown(struct kvm_ctx *ctx)
{
	int i;

	termios_restore();

	if (!ctx || g_vm_preserved)
		return;

	atomic_store(&g_vm_running, false);

	if (atomic_load(&vm_is_paused)) {
		atomic_store(&vm_is_paused, false);
		pthread_mutex_lock(&pause_mutex);
		pthread_cond_broadcast(&pause_cond);
		pthread_mutex_unlock(&pause_mutex);
	}

	finish_luo_session(0);

	if (ctx->fifo_fd >= 0) {
		close(ctx->fifo_fd);
		ctx->fifo_fd = -1;
	}
	if (ctx->fifo_path[0]) {
		unlink(ctx->fifo_path);
		ctx->fifo_path[0] = '\0';
	}

	if (ctx->vcpus) {
		int mmap_size = ctx->vcpu_mmap_size;

		for (i = 0; i < ctx->nvcpu; i++) {
			if (ctx->vcpus[i].run && mmap_size > 0)
				munmap(ctx->vcpus[i].run, mmap_size);
			if (ctx->vcpus[i].vcpu_fd >= 0)
				close(ctx->vcpus[i].vcpu_fd);
		}
		free(ctx->vcpus);
		ctx->vcpus = NULL;
	}

	for (i = 0; i < NVMM_MAX_PCPUS; i++) {
		if (ctx->pcpu_preserve_fds[i] >= 0) {
			close(ctx->pcpu_preserve_fds[i]);
			ctx->pcpu_preserve_fds[i] = -1;
		}
	}

	if (ctx->mem && ctx->mem_size > 0) {
		munmap(ctx->mem, ctx->mem_size);
		ctx->mem = NULL;
	}

	if (ctx->ram_fd >= 0) {
		close(ctx->ram_fd);
		ctx->ram_fd = -1;
	}
	if (ctx->vm_fd >= 0) {
		close(ctx->vm_fd);
		ctx->vm_fd = -1;
	}
	if (ctx->kvm_fd >= 0) {
		close(ctx->kvm_fd);
		ctx->kvm_fd = -1;
	}
	vm_arch_teardown(ctx);
}

/**
 * usage() - Print command line usage help and exit.
 * @progname: Name of executable program.
 */
static void usage(const char *progname)
{
	printf("Usage: %s -s <session_name> [OPTIONS]\n", progname);
	printf("Options:\n");
	printf("  -s, --session <name>      LUO session name (required)\n");
	printf("  -k, --kernel <path>       Path to kernel bzImage/Image (required for cold boot)\n");
	printf("  -i, --initrd <path>       Path to initramfs/initrd\n");
	printf("  -p, --cmdline <cmdline>   Kernel command line arguments\n");
	printf("  -m, --memory <size>       Memory size with optional suffix (K, M, G). Default is MB (default: 128)\n");
	printf("  -c, --cpus <count>        Number of vCPUs (default: 1)\n");
	printf("  -C, --fifo <path>         Path to command FIFO (default: /tmp/nvmm_<session>.fifo)\n");
	printf("  -P, --caps                Query host KVM live update capabilities and exit\n");
	printf("  -h, --help                Show this help message\n");
	printf("\nCommands accepted via control FIFO:\n");
	printf("  suspend [cpu-pool]        Preserve VM via LUO (all vCPUs preserved; optional\n");
	printf("                            host physical CPU pool, e.g. 'cpu1-2' or 'cpu1,cpu3',\n");
	printf("                            to preserve for on-core Caretaker execution).\n");
	printf("  resume                    Cancel preservation and resume VM execution\n");
	printf("  quit                      Gracefully terminate VM\n");
	exit(1);
}

static void parse_mem_size(const char *arg, size_t *mem_size)
{
	char *endptr;

	if (!arg || !*arg) {
		fprintf(stderr, "Invalid memory size argument\n");
		exit(1);
	}
	unsigned long long val = strtoull(arg, &endptr, 10);

	if (val == 0) {
		fprintf(stderr, "Invalid memory size value: %s\n", arg);
		exit(1);
	}

	switch (*endptr) {
	case 'G':
	case 'g':
		*mem_size = (size_t)(val * SZ_1G);
		break;
	case 'M':
	case 'm':
	case '\0':
		*mem_size = (size_t)(val * SZ_1M);
		break;
	case 'K':
	case 'k':
		*mem_size = (size_t)(val * SZ_1K);
		break;
	default:
		fprintf(stderr, "Invalid memory size format: %s\n", arg);
		exit(1);
	}

	*mem_size = ALIGN_UP(*mem_size, HUGEPAGE_2MB_SIZE);
}

/**
 * parse_args() - Parse CLI options and populate VMM configuration struct.
 * @opts: Pointer to VMM configuration struct to populate.
 * @argc: Argument count from main().
 * @argv: Argument vector from main().
 */
static void parse_args(struct vmm_opts *opts, int argc, char **argv)
{
	static const struct option long_options[] = {
		{"session", required_argument, NULL, 's'},
		{"kernel",  required_argument, NULL, 'k'},
		{"initrd",  required_argument, NULL, 'i'},
		{"cmdline", required_argument, NULL, 'p'},
		{"memory",  required_argument, NULL, 'm'},
		{"cpus",    required_argument, NULL, 'c'},
		{"fifo",    required_argument, NULL, 'C'},
		{"caps",    no_argument,       NULL, 'P'},
		{"help",    no_argument,       NULL, 'h'},
		{NULL, 0, NULL, 0}
	};
	int opt;

	opts->kernel_path = NULL;
	opts->initrd_path = NULL;
	opts->cmdline = "";
	opts->mem_size = DEFAULT_MEM_SIZE;
	opts->nvcpu = 1;
	opts->session_name = NULL;
	opts->fifo_path = NULL;
	opts->is_resume = 0;

	while ((opt = getopt_long(argc, argv, "s:k:i:p:m:c:C:Ph",
				  long_options, NULL)) != -1) {
		switch (opt) {
		case 'P': {
			int fd = open(KVM_DEVICE_PATH, O_RDWR);
			if (fd < 0) {
				perror("open " KVM_DEVICE_PATH);
				exit(1);
			}
			int vcpu_pres = ioctl(fd, KVM_CHECK_EXTENSION, KVM_CAP_VCPU_PRESERVE);
			int caretaker = ioctl(fd, KVM_CHECK_EXTENSION, KVM_CAP_CARETAKER);
			close(fd);
			printf("KVM_CAP_VCPU_PRESERVE: %d\n", vcpu_pres > 0 ? 1 : 0);
			printf("KVM_CAP_CARETAKER: %d\n", caretaker > 0 ? 1 : 0);
			exit(0);
		}
		case 'k':
			opts->kernel_path = optarg;
			break;
		case 'i':
			opts->initrd_path = optarg;
			break;
		case 'm':
			parse_mem_size(optarg, &opts->mem_size);
			break;
		case 'c':
			if (optarg && *optarg)
				opts->nvcpu = atoi(optarg);
			if (opts->nvcpu < 1 || opts->nvcpu > NVMM_MAX_VCPUS) {
				fprintf(stderr,
					"Error: vCPU count must be between "
					"1 and %d\n", NVMM_MAX_VCPUS);
				exit(1);
			}
			break;
		case 'p':
			opts->cmdline = optarg;
			break;
		case 's':
			opts->session_name = optarg;
			break;
		case 'C':
			opts->fifo_path = optarg;
			break;
		case 'h':
		default:
			usage(argv[0]);
		}
	}

	if (!opts->session_name) {
		fprintf(stderr, "Error: Session name (-s <name>) is required\n\n");
		usage(argv[0]);
	}
}

/**
 * setup_vm() - Instantiate KVM VM and create guest_memfd RAM storage.
 * @opts: Pointer to VMM configuration options.
 * @ctx: Pointer to KVM VM context to populate.
 */
static void setup_vm(struct vmm_opts *opts, struct kvm_ctx *ctx)
{
	struct kvm_create_guest_memfd gmem;
	int i;

	memset(ctx, 0, sizeof(*ctx));
	for (i = 0; i < NVMM_MAX_PCPUS; i++)
		ctx->pcpu_preserve_fds[i] = -1;
	ctx->fifo_fd = -1;
	init_control_fifo(ctx, opts);
	create_kvm_vm(ctx);

	ctx->mem_size = opts->mem_size;
	memset(&gmem, 0, sizeof(gmem));
	gmem.size = opts->mem_size;
	gmem.flags = GUEST_MEMFD_FLAG_MMAP | GUEST_MEMFD_FLAG_INIT_SHARED;

	ctx->ram_fd = ioctl(ctx->vm_fd, KVM_CREATE_GUEST_MEMFD, &gmem);
	if (ctx->ram_fd < 0)
		die("KVM_CREATE_GUEST_MEMFD");

	if (map_guest_ram(ctx, opts->mem_size) < 0)
		die("mmap mem");

	vm_arch_init(opts, ctx);
}

/**
 * main() - NanoVMM entry point.
 * @argc: Number of CLI arguments.
 * @argv: CLI argument strings.
 *
 * Return: 0 on clean shutdown, non-zero on error.
 */
int main(int argc, char **argv)
{
	struct vmm_opts opts;
	struct kvm_ctx ctx;

	setlinebuf(stdout);
	parse_args(&opts, argc, argv);

	/* Probe and auto-resume from existing LUO session if present */
	if (vm_resume_luo(&opts, &ctx) == 0) {
		return 0;
	}

	/* No preserved LUO session found: require kernel path for cold boot */
	if (!opts.kernel_path) {
		fprintf(stderr,
			"Error: Session '%s' not found, and kernel path "
			"(-k <path>) not provided\n\n",
			opts.session_name);
		usage(argv[0]);
	}

	printf("[NVMM] No preserved LUO session '%s' found. "
	       "Cold booting guest VM...\n", opts.session_name);
	setup_vm(&opts, &ctx);
	setup_vcpus(&opts, &ctx, -1);
	run_vm(&opts, &ctx);

	return 0;
}
