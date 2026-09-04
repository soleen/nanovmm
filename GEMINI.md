# NanoVMM Code Style & Developer Guidelines

This document outlines the coding standards, design rules, and AI agent
guidelines for maintaining the `nanovmm` codebase.

## 1. Linux Kernel Coding Standards
- **Line Length**: Every line in C source files (`.c`), header files (`.h`),
  Makefiles, and documentation MUST be **80 characters or fewer**.
- **Indentation**: Use 8-character tabs for code indentation.
- **Comment Style**: Use standard Linux kernel comment formatting:
  - Single-line comments: `/* ... */`
  - Multi-line comments:
    ```c
    /*
     * Explanation of a complex section
     * of code.
     */
    ```
  - Function documentation: Use Linux kernel-doc style comments above all
    function definitions:
    ```c
    /**
     * function_name() - Short summary description.
     * @param_name: Parameter description.
     *
     * Detailed description of function behavior and return values.
     */
    ```

## 2. Architectural Layering & Zero Preprocessor Conditionals
- **No `#ifdef` in `.c` Files**: NEVER place preprocessor conditionals
  (`#if`, `#ifdef`, `#ifndef`, `#else`, `#elif`, `#endif`) inside `.c` source
  files (`nvmm.c`, `x86_64.c`, `arm64.c`).
- **Header Abstractions**: Place all architecture-specific structure
  definitions, constants, and preprocessor macros inside `nvmm.h`.
- **Architecture Hooks Contract**: Cross-architecture functionality must be
  implemented via abstract function hooks defined in `nvmm.h` and implemented
  by architecture backends (`x86_64.c` and `arm64.c`):
  - `vm_arch_init()` / `vm_arch_post_init()`
  - `vcpu_arch_init()`
  - `handle_arch_exit()`
  - `uart_irq_pulse()`
  - `vcpu_arch_get_pc()` / `vcpu_arch_get_sp()`
  - `vcpu_arch_save_state()` / `vcpu_arch_restore_state()`
  - `vm_arch_preserve_luo()` / `vm_arch_resume_luo()`

## 3. Clean Code & Maintainability Rules
- **No Boilerplate `(void)param;` Casts**: Do not write explicit `(void)param;`
  casts inside function bodies to suppress unused parameter warnings. Use the
  `__maybe_unused` attribute macro (defined as `__attribute__((unused))`) in
  parameter lists instead.
- **Avoid Deep Nesting**: Avoid deep nesting inside function bodies. Use early
  returns, `switch` dispatchers, or extract single-purpose helper functions
  (e.g., `pl011_read()`, `pl011_write()`, `com1_in()`, `com1_out()`,
  `preserve_fd()`, `retrieve_fd()`).
- **No Unnamed Magic Literals**: Avoid literal magic numbers or hardcoded string
  paths inside functions. Define descriptive `#define` macros in `nvmm.h` or the
  top of backend `.c` files (e.g., `KVM_DEVICE_PATH`, `LUO_RAM_NAME`, `SZ_1G`,
  `PANIC_SLEEP_US`, `COM1_IRQ`).

## 4. Compilation & Verification
- Always build C programs statically with optimization and strict warnings:
  ```bash
  make CC=gcc ARCH=x86_64
  make CC=aarch64-linux-gnu-gcc ARCH=arm64
  ```
- Flags used by Makefile: `-g -Os -static -Wall -Wextra -Werror`

## 5. Git Commit Guidelines
- **Line Length**: Every line in git commit messages (subject and body) MUST be
  **72 characters or fewer**.
- **Signed-off-by**: ALWAYS sign off commits (e.g. `git commit -s`) with
  `Signed-off-by: Pasha Tatashin <pasha.tatashin@soleen.com>`.
- **No AI Tags**: NEVER add AI tags or metadata (e.g., `TAG=`, `CONV=`,
  `ORIGINAL_AUTHOR=`) to git commit messages.
- **Formatting**: Use standard Linux kernel commit message style with an
  imperative subject line and concise bulleted summary.
