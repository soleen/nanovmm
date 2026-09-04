# NanoVMM - Lightweight Live-Update Enabled Virtual Machine Monitor

NanoVMM (`nanovmm`) is a minimalist Virtual Machine Monitor (VMM) written in
C for Linux KVM (`/dev/kvm`). Designed for Linux kernel 7.2 and later (Linux 7.2+),
it provides seamless, zero-downtime VM live update using CPU state preservation via
Linux kernel `/dev/liveupdate` and `memfd_create()` descriptors.

---

## Architecture & Layering

NanoVMM is structured into three clean, un-entangled layers with zero
preprocessor `#ifdef` blocks in `.c` files:

```
+-------------------------------------------------------------------+
|                        Core Engine (nvmm.c)                        |
|   CLI Options, POSIX Threads, Terminal Raw Mode, LUO Preservation |
+-------------------------------------------------------------------+
                                  |
                   Architecture Interface Contract
                   (Function Hooks in nvmm.h)
                                  |
       +--------------------------+--------------------------+
       |                                                     |
+------------------------------+             +------------------------------+
| x86_64 Backend (x86_64.c)    |             | ARM64 Backend (arm64.c)      |
| bzImage Protocol, E820 Map,  |             | Flat Image Protocol, DTB,    |
| Identity Page Tables,        |             | GICv3 Interrupt Controller,  |
| 8250 PIO UART at 0x3F8       |             | PL011 MMIO UART at 0x09000000|
+------------------------------+             +------------------------------+
```

1. **Core VMM Engine (`nvmm.c`, `nvmm.h`)**:
   - Command-line argument parsing and option validation.
   - Memory size validation aligned to 2MB hugepage boundaries.
   - POSIX thread management for vCPUs, console input, and control signals.
   - Concurrency-safe condition-variable vCPU pause barrier combining `SIGUSR1`
     interrupts with KVM `immediate_exit` flags.
   - Async-signal-safe `eventfd` notification loop for live update requests.
   - Deferred session completion (`LIVEUPDATE_SESSION_FINISH`) until vCPUs and
     VM registers are verified on resume, ensuring rollback safety.
   - Automatic VM resume rollback if live update preservation fails, including
     control FIFO recovery if a host `kexec` live update is aborted.
   - Immediate whole-VM shutdown on fatal vCPU exits (no zombie threads).
   - Host terminal raw mode (`cfmakeraw`) with fatal signal safety.
   - Kernel panic detection and watchdog monitoring.
   - Stack-buffered console input (`stdin_thread`) with ring buffer overflow
     diagnostics and rate-limited IRQ pulsing.
   - Shared `load_file_into_mem()` loader with bounds checking.
   - Live Update (`LUO`) session creation (`/dev/liveupdate`) and state
     preservation using `memfd_create()` descriptors.
   - Host transition duration measurement and reporting.

2. **Architecture Interface Contract (`nvmm.h`)**:
   - Clean, abstract function hooks implemented by arch backends:
     - `vm_arch_init()`: Boot protocol, memory map, kernel loading.
     - `vm_arch_post_init()`: Post-vCPU device setup (e.g. GICv3 control).
     - `vcpu_arch_init()`: Architecture-specific register setup.
     - `handle_arch_exit()`: Architecture-specific exit dispatch (IO/MMIO).
     - `uart_irq_pulse()`: Assert/deassert serial interrupt lines.
     - `vcpu_arch_get_pc()` / `vcpu_arch_get_sp()`: Extract PC/SP.
     - `vcpu_arch_save_state()` / `vcpu_arch_restore_state()`: Save/restore.
     - `vm_arch_preserve_luo()` / `vm_arch_resume_luo()`: Save/restore devices.

3. **Architecture Backends (`x86_64.c`, `arm64.c`)**:
   - **x86_64**: Linux 64-bit boot protocol (`struct boot_params`), E820
     memory map with MMIO hole, 4-level page tables, GDT setup for 64-bit Long
     Mode, and 8250 PIO serial console at `0x3F8`. Assumes modern x86_64
     hardware with Invariant TSC (`CPUID 0x80000007:EDX[8]`), native KVM TSC
     frequency retrieval (`KVM_GET_TSC_KHZ`), 1GB large page support (`pdpe1gb`)
     for high-memory identity mapping above 4GB, and Linux kernel 7.2+ KVM ABI
     for direct two-step `KVM_GET_SUPPORTED_CPUID` and dynamic `KVM_GET_MSR_INDEX_LIST`
     discovery without legacy fallback tables.
   - **ARM64**: Flat Linux Image boot protocol, self-contained binary Flattened
     Device Tree (FDT) generator with buffer overflow protection writing
     directly into guest memory, ARM GICv3 interrupt controller with
     multi-vCPU redistributors and CPU interface registers, and AMBA PL011
     MMIO serial console at `0x09000000`. Assumes Linux kernel 7.2+ ARM64 KVM
     ABI with standard core register layouts (`KVM_REG_ARM_CORE_REG`).

---

## Memory & State Preservation Architecture

During a live update request (`SIGUSR2` signal or console hotkey), NanoVMM
preserves VM state without losing guest CPU or device context:

1. **KVM VM Handle (`LUO_VM_TOKEN`)**:
   - Preserves KVM VM instance (`ctx->vm_fd`) across host live update,
     restoring the VM container on the next kernel.
2. **Guest RAM (`LUO_RAM_TOKEN`)**:
   - Memory is instantiated via KVM `guest_memfd` (`KVM_CREATE_GUEST_MEMFD`
     with `GUEST_MEMFD_FLAG_MMAP | GUEST_MEMFD_FLAG_INIT_SHARED`) and mapped
     into KVM with `KVM_SET_USER_MEMORY_REGION2` (`KVM_MEM_GUEST_MEMFD`),
     preserving guest physical RAM across host kernel `kexec` reboots.
3. **Unified Machine State (`LUO_STATE_TOKEN`)**:
   - Encapsulates all non-RAM VM state in a single versioned structure
     (`struct nvmm_machine_state`), preserved and restored atomically.
   - **VMM Metadata**: Magic (`NVMMSTAT`), format version, RAM size, vCPU
     count, and transition timestamps.
   - **vCPU State**:
     - **x86_64**: Complete register state (`REGS`, `SREGS`, `MSRs`,
       `LAPIC`, `XSAVE`, `XCRs`, `MP_STATE`, `EVENTS`).
     - **ARM64**: All active vCPU registers (X0-X30, SP_EL1, PSTATE,
       TTBR0/1_EL1, SCTLR_EL1, TCR_EL1, timer counters, etc.) dynamically
       enumerated via `KVM_GET_REG_LIST`.
   - **Architecture Peripherals & Timers**:
     - **x86_64**: Master/Slave PIC, IOAPIC (`KVM_GET_IRQCHIP`), PIT2 timer
       (`KVM_GET_PIT2`), and KVM clock (`KVM_GET_CLOCK`).
     - **ARM64**: GICv3 Distributor registers (CTLR, IGROUPR, ISENABLER,
       ISPENDR, ISACTIVER, IPRIORITYR, ICFGR, IROUTER), Redistributor
       registers (CTLR, IGROUPR0, ISENABLER0, ISPENDR0, ISACTIVER0,
       IPRIORITYR0, ICFGR0/1), CPU interface system registers (`SYS_ICC_*`),
       and PL011 UART interrupt masks.

---

## Guest Heartbeat & Monitoring

NanoVMM includes an integrated guest heartbeat generator (`guest_heartbeat`)
and host monitor thread (`guest_monitor`):

1. **Guest Heartbeat Service (`guest_heartbeat.c`)**:
   - Executes inside the guest rootfs (compiled statically).
   - Writes periodic, monotonically incrementing heartbeat records with
     sub-millisecond timestamps directly into immovable guest memory or logs.
   - Preserves continuous counter sequences across host live kernel updates
     without cold-reboot counter resets.

2. **Host Monitor Thread (`guest_monitor.c`)**:
   - Runs as a background POSIX thread inside NanoVMM.
   - Monitors guest heartbeat progress and logs live update downtime
     measurements to `/tmp/guest_monitor.log`.

---

## Command Line Usage

```bash
nvmm -s <session_name> [OPTIONS]
```

### Options Reference

| Flag | Argument | Description | Default |
|------|----------|-------------|---------|
| `-s` | `<name>` | LUO session name (required) | None |
| `-k` | `<path>` | Path to kernel image (required for cold boot) | None |
| `-i` | `<path>` | Path to initramfs/initrd image | Optional |
| `-p` | `<cmdline>` | Kernel command-line parameters | `""` |
| `-m` | `<size>` | Guest RAM size (supports K, M, G suffixes) | `128M` |
| `-c` | `<count>`| Number of virtual CPUs | `1` |
| `-b` | None | Bind vCPUs to host physical CPUs (1:1 mapping) | Disabled |
| `-O` | None | Enable Orphan CPU mode | Disabled |
| `-C` | `<path>` | Path to command FIFO | `/tmp/nvmm_<session>.fifo` |
| `-h` | None | Display command-line usage help | N/A |

### Example Commands

#### Cold Boot (x86_64)
```bash
./nvmm -s ovm1 -k /boot/vmlinuz -i /boot/initramfs.cpio.gz \
       -p "console=ttyS0 quiet" -m 2G -c 2
```

#### Cold Boot (ARM64)
```bash
./nvmm -s ovm1 -k /boot/Image -i /boot/initramfs.cpio.gz \
       -p "console=ttyAMA0 quiet" -m 1G -c 1
```

#### Auto-Resume from Preserved Session
```bash
./nvmm -s ovm1
```

---

## Runtime Control FIFO Interface

While NanoVMM is running, runtime control commands can be written to its FIFO
(default: `/tmp/nvmm_<session_name>.fifo`):

```bash
# Suspend and preserve VM state via LUO (default strategy)
echo "suspend" > /tmp/nvmm_ovm1.fifo

# Suspend with explicit strategy:
# - default / all: Preserve all target pCPUs (if orphan mode) and all vCPUs
# - cpu:           Preserve all target pCPUs and all vCPUs
# - vcpu:          Preserve all vCPUs (and 0 pCPUs)
# - cpuX / cpuX-Y: Preserve specific host physical CPU(s) and all vCPUs
# - vcpuX / vcpuX-Y: Preserve specific guest vCPU(s)
#
# Rule: If vCPUs are explicitly specified, ALL guest vCPUs must be listed.
#       pCPUs do NOT have to be all specified.
echo "suspend cpu1,cpu2" > /tmp/nvmm_ovm1.fifo
echo "suspend cpu1-2,vcpu0-1" > /tmp/nvmm_ovm1.fifo
echo "suspend vcpu" > /tmp/nvmm_ovm1.fifo

# Cancel preservation and resume VM execution
echo "resume" > /tmp/nvmm_ovm1.fifo

# Terminate VM cleanly
echo "quit" > /tmp/nvmm_ovm1.fifo
```

---

## Building NanoVMM

NanoVMM uses standard Make targets and requires a static C build toolchain.

### x86_64 Build
```bash
make CC=gcc ARCH=x86_64
```

### ARM64 Cross-Build
```bash
make CC=aarch64-linux-gnu-gcc ARCH=arm64
```

### Clean
```bash
make clean
```
