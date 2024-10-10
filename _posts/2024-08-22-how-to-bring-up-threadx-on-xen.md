---
title: "how to bring up threadx on xen"
date: 2024-08-22
categories: [blog, embedded]
tags: [threadx, xen]
---

## what are xen & threadx?
[xen](https://xenproject.org) is a type-I hypervisor, [threadx](https://threadx.io) is a RTOS.

## why we need virtualization?
in many industries, it is necessary to be able to run different operating systems (or even no operating system at all) to meet various business requirements.
multiple OS could be run without hypervisor.
however, the system mostly restart if one core crashed.
the embedded field has extremely high requirements for stability, and virtualization can enhance stability.

others include, resource efficiency, isolation and security, scalability and flexibility, and so on.

## why xen & threadx?
QNX is primarily used in the automotive sector and is a closed-source operating system.

## prerequisites
in the development environment, I used QEMU to emulate one board, and the board's SoC adopts an ARM multi-core processor.
using QEMU is flexible, low-cost, convenient for debugging (the most important aspect), and easy to promote (users don't need to purchase a development board).

all the reference implementation: <https://github.com/tw-embedded/baize-board>

## whole architecture
![architecture image](../assets/2024.08/picture1.png)

Exception Levels (EL): hierarchical privilege levels in ARM architecture.
it determines the amount of control and access a process or code running at a particular level has.
there are four levels, from EL0 to EL3, each with different levels of privilege:

**EL0**: the lowest privilege level, typically used for user applications.

**EL1**: used for operating system kernels and drivers.

**EL2**: used for hypervisors in virtualization scenarios.

**EL3**: the highest privilege level, usually for secure monitor code and system management.

## all key steps

### step 1. build the threadx project

after cloning the project repository, create a new build folder for porting to xen:

```bash
cp -r ./ports/cortex_a53/gnu/example_build/sample_threadx ./ports/cortex_a53/gnu/xen_build
```

yes, here I selected cortex-a53 as target. added several cmake files:

```diff
cmake/aarch64-linux-gnu.cmake
+set(CMAKE_C_COMPILER    aarch64-linux-gnu-gcc)
+set(CMAKE_CXX_COMPILER  aarch64-linux-gnu-g++)
+set(AS                  aarch64-linux-gnu-as)
+set(AR                  aarch64-linux-gnu-ar)
+set(OBJCOPY             aarch64-linux-gnu-objcopy)
+set(OBJDUMP             aarch64-linux-gnu-objdump)
+set(SIZE                aarch64-linux-gnu-size)
+
+set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
+set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
+set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
+set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
+
+# this makes the test compiles use static library option so that we don't need to pre-set linker flags and scripts
+set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
+
+set(CMAKE_C_FLAGS   "${MCPU_FLAGS} ${VFP_FLAGS} ${SPEC_FLAGS} -fdata-sections -ffunction-sections" CACHE INTERNAL "c compiler flags")
+set(CMAKE_CXX_FLAGS "${MCPU_FLAGS} ${VFP_FLAGS} -fdata-sections -ffunction-sections -fno-rtti -fno-exceptions -mlong-calls" CACHE INTERNAL "cxx compiler flags")
+set(CMAKE_ASM_FLAGS "${MCPU_FLAGS} ${VFP_FLAGS} -x assembler-with-cpp" CACHE INTERNAL "asm compiler flags")
+set(CMAKE_EXE_LINKER_FLAGS "${MCPU_FLAGS} ${LD_FLAGS} -Wl,--gc-sections" CACHE INTERNAL "exe link flags")
+
+SET(CMAKE_C_FLAGS_DEBUG "-Og -g -ggdb3" CACHE INTERNAL "c debug compiler flags")
+SET(CMAKE_CXX_FLAGS_DEBUG "-Og -g -ggdb3" CACHE INTERNAL "cxx debug compiler flags")
+SET(CMAKE_ASM_FLAGS_DEBUG "-g -ggdb3" CACHE INTERNAL "asm debug compiler flags")
+
+SET(CMAKE_C_FLAGS_RELEASE "-O3" CACHE INTERNAL "c release compiler flags")
+SET(CMAKE_CXX_FLAGS_RELEASE "-O3" CACHE INTERNAL "cxx release compiler flags")
+SET(CMAKE_ASM_FLAGS_RELEASE "" CACHE INTERNAL "asm release compiler flags")

cmake/cortex_a53.cmake
+set(CMAKE_SYSTEM_NAME Generic)
+set(CMAKE_SYSTEM_PROCESSOR cortex-a53)
+
+set(THREADX_ARCH "cortex_a53")
+set(THREADX_TOOLCHAIN "gnu")
+
+set(MCPU_FLAGS "-mcpu=cortex-a53")
+set(VFP_FLAGS "")
+
+include(${CMAKE_CURRENT_LIST_DIR}/aarch64-linux-gnu.cmake)

ports/cortex_a53/gnu/CMakeLists.txt
+target_sources(${PROJECT_NAME} PRIVATE
+    ${CMAKE_CURRENT_LIST_DIR}/src/tx_initialize_low_level.S
+    ${CMAKE_CURRENT_LIST_DIR}/src/tx_thread_context_restore.S
+    ${CMAKE_CURRENT_LIST_DIR}/src/tx_thread_context_save.S
+    ${CMAKE_CURRENT_LIST_DIR}/src/tx_thread_fp_disable.c
+    ${CMAKE_CURRENT_LIST_DIR}/src/tx_thread_fp_enable.c
+    ${CMAKE_CURRENT_LIST_DIR}/src/tx_thread_interrupt_control.S
+    ${CMAKE_CURRENT_LIST_DIR}/src/tx_thread_interrupt_disable.S
+    ${CMAKE_CURRENT_LIST_DIR}/src/tx_thread_interrupt_restore.S
+    ${CMAKE_CURRENT_LIST_DIR}/src/tx_thread_schedule.S
+    ${CMAKE_CURRENT_LIST_DIR}/src/tx_thread_stack_build.S
+    ${CMAKE_CURRENT_LIST_DIR}/src/tx_thread_system_return.S
+    ${CMAKE_CURRENT_LIST_DIR}/src/tx_timer_interrupt.S
+)
+
+target_include_directories(${PROJECT_NAME} PUBLIC
+    ${CMAKE_CURRENT_LIST_DIR}/inc
+)
+
+set(APP_NAME threadxen)
+set(EXE_NAME ${APP_NAME}.elf)
+set(LDS ${CMAKE_CURRENT_LIST_DIR}/xen_build/threadx.ld)
+add_executable(${EXE_NAME})
+target_link_libraries(${EXE_NAME} ${PROJECT_NAME})
+target_link_options(${EXE_NAME} PRIVATE -T ${LDS})
+target_sources(${EXE_NAME} PRIVATE
+    # {{BEGIN_TARGET_SOURCES}}
+       ${CMAKE_CURRENT_LIST_DIR}/xen_build/main.c
+       ${CMAKE_CURRENT_LIST_DIR}/xen_build/gicv3_gicd.c
+       ${CMAKE_CURRENT_LIST_DIR}/xen_build/gicv3_gicr.c
+       ${CMAKE_CURRENT_LIST_DIR}/xen_build/sp804_timer.c
+       ${CMAKE_CURRENT_LIST_DIR}/xen_build/timer_interrupts.c
+       ${CMAKE_CURRENT_LIST_DIR}/xen_build/mp_mutexes.s
+       ${CMAKE_CURRENT_LIST_DIR}/xen_build/startup.s
+       ${CMAKE_CURRENT_LIST_DIR}/xen_build/v8_aarch64.s
+       ${CMAKE_CURRENT_LIST_DIR}/xen_build/v8_utils.s
+       ${CMAKE_CURRENT_LIST_DIR}/xen_build/vectors.s
+       ${CMAKE_CURRENT_LIST_DIR}/xen_build/pecoff.s
+    # {{END_TARGET_SOURCES}}
+)
+add_custom_command(
+    TARGET ${EXE_NAME}
+    POST_BUILD
+    COMMAND ${CMAKE_OBJCOPY} ${EXE_NAME} -O binary ${APP_NAME}
+)
```

execute the following commands to build threadx:

```bash
cmake -Bbuild -GNinja -DCMAKE_TOOLCHAIN_FILE=cmake/cortex_a53.cmake
cmake --build ./build
```

the binary file is in the folder:

```bash
➜  threadx git:(c349997) ls build/ports/cortex_a53/gnu
CMakeFiles  cmake_install.cmake  threadxen  threadxen.elf
➜  threadx git:(c349997) file build/ports/cortex_a53/gnu/threadxen.elf
build/ports/cortex_a53/gnu/threadxen.elf: ELF 64-bit LSB executable, ARM aarch64, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux-aarch64.so.1, for GNU/Linux 3.7.0, BuildID[sha1]=40e3d7911d897c77c80c2058d9aadf4d99843761, not stripped
```

### step 2. update device tree of xen

```text
		cp_threadx: cpupool1 {
			compatible = "xen,cpupool";
			cpupool-cpus = <&cpu7>;
			cpupool-sched = "null";
		};
		...
		domus {
			compatible = "xen,domain";
			#address-cells = <2>;
			#size-cells = <2>;
			cpus = <1>;
			memory = <0 0x10000>;
			vpl011;
			domain-cpupool = <&cp_threadx>;

			module@1 {
				compatible = "multiboot,kernel", "multiboot,module";
				xen,uefi-binary = "threadxen";
				bootargs = "console=ttyAMA0";
			};
		};
```

here, I allocated one CPU for threadx, which means that threadx does not need to support SMP for the time being.
the memory available to threadx is very limited, with only 0x10000 KB (64M).
additionally, threadx is being booted in a typical dom0-less configuration.
dom0-less refers to a virtualization setup, particularly in xen hypervisor, where multiple guest VMs (virtual machine) are launched directly without relying on the traditional dom0 (the management domain) to start or manage them, improving boot time and system performance.

### step 3. boot threadx

as expected, the boot failed.

![boot image](../assets/2024.08/s1.png)

review the most recent non-failing logs and trace them back to the corresponding code。

```text
(XEN) *** LOADING DOMU cpus=1 memory=10000KB ***
(XEN) Loading d1 kernel from boot module @ 0000000127aaa000
```

it is in the `kernel_probe` function of xen.

![image](../assets/2024.08/s2.png)

the threadx image is neither a uImage nor 32-bit, so we should next examine the `kernel_zimage64_probe` function.

```c
static int __init kernel_zimage64_probe(struct kernel_info *info,
                                        paddr_t addr, paddr_t size)
{
    /* linux/Documentation/arm64/booting.txt */
    struct {
        uint32_t magic0;
        uint32_t res0;
        uint64_t text_offset;  /* Image load offset */
        uint64_t res1;
        uint64_t res2;
        /* zImage V1 only from here */
        uint64_t res3;
        uint64_t res4;
        uint64_t res5;
        uint32_t magic1;
        uint32_t res6;
    } zimage;
    uint64_t start, end;

    if ( size < sizeof(zimage) )
        return -EINVAL;

    copy_from_paddr(&zimage, addr, sizeof(zimage));

    if ( zimage.magic0 != ZIMAGE64_MAGIC_V0 &&
         zimage.magic1 != ZIMAGE64_MAGIC_V1 )
        return -EINVAL;
```

`kernel_zimage64_probe` checks the magic number, the macros are defined here:

```c
#define ZIMAGE64_MAGIC_V0 0x14000008
#define ZIMAGE64_MAGIC_V1 0x644d5241 /* "ARM\x64" */
```

open the documentation in the comment of the `kernel_zimage64_probe` function:

![image](../assets/2024.08/s3.png)

check the header of linux kernel image layout:

![image](../assets/2024.08/s4.png)

check the file format of linux kernel image:

```bash
➜  linux git:(6a77b390) file ./build/arch/arm64/boot/Image
Image: MS-DOS executable PE32+ executable (EFI application) Aarch64 (stripped to external PDB), for MS Windows
```

clearly, the linux image header contains a pe-format header. the threadx image needs it also.

### step 4. add pecoff (Portable Executable and Common Object File Format) header

pecoff (Portable Executable/Common Object File Format) is the file format used by Microsoft Windows for executable files, dynamic link libraries, and object files, extending the common object file format (COFF) with additional features specific to Windows.

first, add a new file [threadx/ports/cortex_a53/gnu/xen_build/pecoff.s](https://github.com/tw-embedded/threadx/blob/master/ports/cortex_a53/gnu/xen_build/pecoff.s) and include it in the build process.

second, add pecoff section to the start of the image.

```diff
threadx/ports/cortex_a53/gnu/xen_build/threadx.ld
ENTRY(_threadxen_start)
SECTIONS
{
    . = 0x80000000; /* THREADXEN_VA */
    _threadxen_start = .;
+   .pecoff : {
+       KEEP(*(.pecoff))
+   }
```

### step 5. boot threadx

no obvious error logs.

![image](../assets/2024.08/s5.png)

the `kernel_probe` function has finished executing (confirm this through step-by-step debugging).

next, verify the subsequent execution flow: `kernel_probe()` -> `construct_domU()` -> `create_domUs()` -> `start_xen()`.

arrive at the key function `start_xen`:

```c
/* C entry point for boot CPU */
void __init start_xen(unsigned long boot_phys_offset,
                      unsigned long fdt_paddr)
{
    ...

    if ( acpi_disabled )
    {
        create_domUs();
        alloc_static_evtchn();
    }

    /*
     * This needs to be called **before** heap_init_late() so modules
     * will be scrubbed (unless suppressed).
     */
    discard_initial_modules();

    heap_init_late();

    init_trace_bufs();

    init_constructors();

    console_endboot();

    /* Hide UART from DOM0 if we're using it */
    serial_endboot();

    if ( (rc = xsm_set_system_active()) != 0 )
        panic("xsm: unable to switch to SYSTEM_ACTIVE privilege: %d\n", rc);

    system_state = SYS_STATE_active;

    for_each_domain( d )
        domain_unpause_by_systemcontroller(d);

    /* Switch on to the dynamically allocated stack for the idle vcpu
     * since the static one we're running on is about to be freed. */
    memcpy(idle_vcpu[0]->arch.cpu_info, get_cpu_info(),
           sizeof(struct cpu_info));
    switch_stack_and_jump(idle_vcpu[0]->arch.cpu_info, init_done);
}
```

final stack switch and jump, and single-step debugging confirms execution reaches this point.

![image](../assets/2024.08/s6.png)

the boot address of the virtual machine can be found in the logs:

![image](../assets/2024.08/s7.png)

set a breakpoint:

![image](../assets/2024.08/s8.png)

GDB stopped at the breakpoint:

![image](../assets/2024.08/s9.png)

clearly, this instruction is the first instruction of the pecoff header we added.

![image](../assets/2024.08/s10.png)

debugging, the threadx VM crashed because it attempts to access the EL3 register (the default threadx example code is started from bare-metal), while threadx is running in EL1 in the current system.

modify the jump address to `el1_entry_aarch64` in the pecoff header:

![image](../assets/2024.08/s11.png)

step-by-step debugging, it trapped in hypervisor:

![image](../assets/2024.08/s12.png)

here, 0x80054e30 is program address. obviously, the address accessed by function `EnableGICD` exceeds the range allocated by xen.

hence, it causes a trap into the hypervisor xen.

### step 6. update memory layout of threadx

threadx calls the function `EnableGICD` directly in sample `startup.s` before initializing the MMU, so the implicit information is that the virtual addresses and physical addresses are the same in the memory layout.

it is not perfect, but just follow it now.

from boot log, the physical address of threadx VM is 0x40000000.

```diff
ports/cortex_a53/gnu/xen_build/threadx.ld
+   . = 0x40000000; /* THREADXEN_VA */
-   . = 0x80000000; /* THREADXEN_VA */
    _threadxen_start = .;
    .pecoff : {
        KEEP(*(.pecoff))
    }
```

rebuild threadx and restart debugging.

`EnableGICD` still caused a trap:

![image](../assets/2024.08/s13.png)

check the source of `EnableGICD`:

```c
GICv3_distributor __attribute__((section(".gicd"))) gicd;

void EnableGICD(GICDCTLRFlags_t flags)
{
    gicd.GICD_CTLR |= flags;
}
```

check the `.gicd` section in lds:

```text
ports/cortex_a53/gnu/xen_build/threadx.ld
    /*
     * GICv3 distributor
     */
    .gicd 0x2f000000 (NOLOAD):
    {
        *(.gicd)
    }
```

so 0x2f000000 is the physical address of gicd, of course, it need to be updated.

### step 7. update GIC address space

as we known, xen has interrupt virtualization capabilities.

the GIC (Generic Interrupt Controller) operated within VM is virtualized by xen, meaning the VM does not directly access the hardware GIC.

interrupt requests are first received by xen, which then forwards these interrupts to the corresponding VM for handling.

this allows xen to manage and allocate interrupts effectively, enabling efficient sharing and isolation of hardware resources in a multiple VM environment.

the address space of GIC is allocated by xen.

check the gicd base from xen source:

`create_domUs(void)`/`construct_domU()`/`prepare_dtb_domU()`/`make_gic_domU_node()`

```c
static int __init make_gic_domU_node(struct kernel_info *kinfo)
{
    switch ( kinfo->d->arch.vgic.version )
    {
#ifdef CONFIG_GICV3
    case GIC_V3:
        return make_gicv3_domU_node(kinfo);
#endif
    case GIC_V2:
        return make_gicv2_domU_node(kinfo);
    default:
        panic("Unsupported GIC version\n");
    }
}
```

here, the SoC uses GIC v3.

```c
static int __init make_gicv3_domU_node(struct kernel_info *kinfo)
{
    void *fdt = kinfo->fdt;
    int res = 0;
    __be32 *reg, *cells;
    const struct domain *d = kinfo->d;
    /* Placeholder for interrupt-controller@ + a 64-bit number + \0 */
    char buf[38];
    unsigned int i, len = 0;

    snprintf(buf, sizeof(buf), "interrupt-controller@%"PRIx64,
             vgic_dist_base(&d->arch.vgic));

    res = fdt_begin_node(fdt, buf);
    if ( res )
        return res;

    res = fdt_property_cell(fdt, "#address-cells", 0);
    if ( res )
        return res;

    res = fdt_property_cell(fdt, "#interrupt-cells", 3);
    if ( res )
        return res;

    res = fdt_property(fdt, "interrupt-controller", NULL, 0);
    if ( res )
        return res;

    res = fdt_property_string(fdt, "compatible", "arm,gic-v3");
    if ( res )
        return res;

    /* reg specifies all re-distributors and Distributor. */
    len = (GUEST_ROOT_ADDRESS_CELLS + GUEST_ROOT_SIZE_CELLS) *
          (d->arch.vgic.nr_regions + 1) * sizeof(__be32);
    reg = xmalloc_bytes(len);
    if ( reg == NULL )
        return -ENOMEM;
    cells = reg;

    dt_child_set_range(&cells, GUEST_ROOT_ADDRESS_CELLS, GUEST_ROOT_SIZE_CELLS,
                       vgic_dist_base(&d->arch.vgic), GUEST_GICV3_GICD_SIZE);

    for ( i = 0; i < d->arch.vgic.nr_regions; i++ )
        dt_child_set_range(&cells,
                           GUEST_ROOT_ADDRESS_CELLS, GUEST_ROOT_SIZE_CELLS,
                           d->arch.vgic.rdist_regions[i].base,
                           d->arch.vgic.rdist_regions[i].size);

    res = fdt_property(fdt, "reg", reg, len);
    xfree(reg);
    if (res)
        return res;

    res = fdt_property_cell(fdt, "linux,phandle", kinfo->phandle_gic);
    if (res)
        return res;

    res = fdt_property_cell(fdt, "phandle", kinfo->phandle_gic);
    if (res)
        return res;

    res = fdt_end_node(fdt);

    return res;
}
```

**xen passes hardware information to the VM through the device tree.**

here, I temporarily hardcoded the GIC address into the threadx source code but support device trees.

to confirm the addresses of the GIC-v3 related registers, continue reading the source code, use GDB for debugging, or add print statements.

ultimately, the GIC address information obtained is as follows:

```text
gicd base 0x3001000

gicr base 0x3020000, size 0x1000000
```

then hardcode these addresses:

```diff
threadx/ports/cortex_a53/gnu/xen_build/threadx.ld
    /*
     * GICv3 distributor
     */
-   .gicd 0x2f000000 (NOLOAD):
+   .gicd 0x3001000 (NOLOAD):
    {
        *(.gicd)
    }

    /*
     * GICv3 redistributors
     * 128KB for each redistributor in the system
     */
-   .gicr 0x2f100000 (NOLOAD):
+   .gicr 0x3020000 (NOLOAD):
    {
        *(.gicr)
    }
```

after updated the GIC address, the function `EnableGICD` can complete execution.

PLACEHOLDER: how does xen implement interrupt virtualization?

### step 8. go to main

upon continuing execution, a crash is still encountered before `main`.

the instruction that caused the crash is a call to `memset`.

![image](../assets/2024.08/s14.png)

of course PLT (Procedure Linkage Table) could not be used here.

I added one simple libc ([rtos/libc](https://github.com/tw-embedded/baize-board/tree/master/rtos/libc)) for threadx to solve this issue.

disable the standard libraries and startup files.

```diff
cmake/aarch64-linux-gnu.cmake
-set(CMAKE_C_FLAGS   "${MCPU_FLAGS} ${VFP_FLAGS} ${SPEC_FLAGS} -fdata-sections -ffunction-sections" CACHE INTERNAL "c compiler flags")
+set(CMAKE_C_FLAGS   "${MCPU_FLAGS} ${VFP_FLAGS} ${SPEC_FLAGS} -nostdlib -fdata-sections -ffunction-sections" CACHE INTERNAL "c compiler flags")

cmake/cortex_a53.cmake
+set(LD_FLAGS "-nostartfiles")

ports/cortex_a53/gnu/CMakeLists.txt
+target_link_libraries(${APP_NAME} ${CMAKE_SOURCE_DIR}/../libc/build/libc.a)
```

finally, it comes the `main` function.

### step 9. printf

now we have entered the world of `C` language!

being able to use printf is a good idea!

linux must support early print on xen, so check linux source code:

```c
linux/drivers/tty/hvc/hvc_xen.c
static int dom0_write_console(uint32_t vtermno, const char *str, int len)
{
	int rc = HYPERVISOR_console_io(CONSOLEIO_write, len, (char *)str);
	if (rc < 0)
		return rc;

	return len;
}
static void xenboot_earlycon_write(struct console *console,
				  const char *string,
				  unsigned len)
{
	dom0_write_console(0, string, len);
}

static int __init xenboot_earlycon_setup(struct earlycon_device *device,
					    const char *opt)
{
	device->con->write = xenboot_earlycon_write;
	return 0;
}
EARLYCON_DECLARE(xenboot, xenboot_earlycon_setup);
```

`HYPERVISOR_console_io` is defined here:

```c
linux/arch/arm64/xen/hypercall.s

#define XEN_IMM 0xEA1

#define HYPERCALL_SIMPLE(hypercall)		\
ENTRY(HYPERVISOR_##hypercall)			\
	mov x16, #__HYPERVISOR_##hypercall;	\
	hvc XEN_IMM;				\
	ret;					\
ENDPROC(HYPERVISOR_##hypercall)

#define HYPERCALL3 HYPERCALL_SIMPLE

HYPERCALL3(console_io);
```

obviously, the VM obtains xen's print services through a hypercall instruction.

next, port this functionality to threadx.

[ports/cortex_a53/gnu/xen_build/hypercall.s](https://github.com/tw-embedded/threadx/blob/master/ports/cortex_a53/gnu/xen_build/hypercall.s)

[ports/cortex_a53/gnu/xen_build/xen.h](https://github.com/tw-embedded/threadx/blob/master/ports/cortex_a53/gnu/xen_build/xen.h)

try to print something:

![image](../assets/2024.08/s15.png)

yes, it is!

![image](../assets/2024.08/s16.png)

i want to use `printf` but `HYPERVISOR_console_io`.

```diff
ports/cortex_a53/gnu/CMakeLists.txt
+${CMAKE_CURRENT_LIST_DIR}/xen_build/putc.c

ports/cortex_a53/gnu/xen_build/putc.c
+#include <stdint.h>
+#include <stddef.h>
+
+#define CONSOLEIO_write 0
+void HYPERVISOR_console_io(int no, size_t size, uint8_t *str);
+
+int console_putc(unsigned char c)
+{
+	HYPERVISOR_console_io(CONSOLEIO_write, 1, &c);
+	return 1;
+}
```

now, `printf` works.

### step 10. add timer

the main function is responsible for two tasks: initializing hardware (GIC, timer) and starting threadx.

```c
int main(void)
{
    printf("threadx\n");

    /* Initialize timer. */
    init_timer();

    /* Enter ThreadX. */
    tx_kernel_enter();

    return 0;
}
```

since the GIC has already been configured with the address space, now focus on the timer.

timer is a core component of the OS.

by providing periodic interrupts, the OS schedules tasks efficiently to achieve effective multitasking and system operation.

to enable the timer, the main considerations are the timer mechanism, GIC interrupt handling, the timer interrupt configuration, and the timer configuration.

#### 10.1 timer mechanism

according to 'AArch64 Programmer's Guides - Generic Timer', arm-v8 includes the generic timer.

the generic timer provides a standardized timer framework for arm cores.

![image](../assets/2024.08/s17.png)

the number of timers that a core provides (depends on which extensions are implemented):

![image](../assets/2024.08/s18.png)

the virtual count allows a hypervisor to show virtual time to a virtual machine (VM).
for example, a hypervisor could hide the passage of time when the VM was not scheduled.
this means that the virtual count can represent time experienced by the VM, rather than wall clock time.

so choose virtual timer as threadx OS tick.

the interrupt ID (INTID) that is used for each timer is defined by the Server Base System Architecture (SBSA), shown here:

![image](../assets/2024.08/s19.png)

PLACEHOLDER: how does xen implement timer virtualization?

#### 10.2 GIC interrupt handling

GICv3 (Generic Interrupt Controller version 3) is an ARM architecture interrupt controller that efficiently manages interrupts in multi-core processors, supports a larger number of interrupt sources, and introduces system-level and virtualization-related interrupt management features.

according to 'Arm Generic Interrupt Controller v3 and v4 Overview', the register interface of a GICv3 interrupt controller is split into three groups:

- distributor interface

- redistributor interface

- CPU interface

![image](../assets/2024.08/s20.png)

each interrupt source is identified by an ID number, which is referred to as an INTID.
the interrupt types that are introduced in the preceding list are defined in terms of ranges of INTIDs:

![image](../assets/2024.08/s21.png)

In terms of scope, the timer interrupt belongs to PPI (Private Peripheral Interrupt).

note: timers can be configured to generate an interrupt.
the interrupt frome a core's timer can only be delivered to that core.

this means there is no need to configure gicr for timer interrupt.

#### 10.3 timer interrupt configuration

configuring the Arm GIC, refer to 'Arm Generic Interrupt Controller v3 and v4 Overview' section 5.

at last, check the interrupt service routine:

```c
ports/cortex_a53/gnu/xen_build/startup.s
el1_entry_aarch64:
    // just check el by manual
    mrs x1, CurrentEL

    // load el1 interrupt vector
    ldr x1, =el1_vectors
    virt_to_phys x1
    msr VBAR_EL1, x1

ports/cortex_a53/gnu/xen_build/vectors.s
el1_vectors:
c0sync1: B c0sync1

    .balign 0x80
c0irq1: B irqFirstLevelHandler
......
irqFirstLevelHandler:
  MSR      SPSel, 0
  STP      x29, x30, [sp, #-16]!
  BL       _tx_thread_context_save
  BL       irqHandler
  B        _tx_thread_context_restore
```

#### 10.4 virtual timer configuration

configuring the generic timer, refer to 'AArch64 Programmer's Guides - Generic Timer' section 3.3 & 3.4.

EL1 virtual timer has the following three system registers:

- **CNTV_CTL_EL0**: control register

- **CNTV_CVAL_EL0**: comparator value

- **CNTV_TVAL_EL0**: timer value

NOTE: EL0 access to these timers is controlled by `CNTKCTL_EL1`.

using the timer (TVAL) register to configure a timer. the timer register, TVAL, is a 32-bit register.
software needs a timer event in X ticks of the clock, software can write X to TVAL.

the generation of interrupts is controlled through the CTL register, using these fields:

- **ENABLE**: 1 to enables the timer.

- **IMASK**: interrupt mask. 1 to mask interrupt generation.

- **ISTATUS**: when ENABLE==1, reports whether the timer is firing.

here is how to operate the CNTV_CTL_EL0 register:

```c
// Accessors for the architected generic timer registers
#define ARM_ARCH_TIMER_ENABLE   (1 << 0)
#define ARM_ARCH_TIMER_IMASK    (1 << 1)
#define ARM_ARCH_TIMER_ISTATUS  (1 << 2)

static void ArmWriteCntvCtl(uint64_t value)
{
    // Write to CNTV_CTL (Virtual Timer Control Register)
    __asm__ __volatile__("ldr x0, %0\n\t"
                         "msr cntv_ctl_el0, x0\n\t"
                         :
                         :"m"(value)
                         :"memory");
}
```

start debugging and enter the interrupt handler, where you can see that the INTID is 27, which is as expected:

![image](../assets/2024.08/s22.png)

single-step debugging, crash：

![image](../assets/2024.08/s23.png)

check the source:

![image](../assets/2024.08/s24.png)

it is clear that the registers of EL3 are being operated here, and the modification plan is also very simple: add a compile-time macro switch `EL1`.

![image](../assets/2024.08/s25.png)

after modification, `_tx_thread_context_save` has finished executing, it is entering the `irqHandler` function.

![image](../assets/2024.08/s26.png)

function `irqHandler` is arranged in timer.c temporarily.

```c
ports/cortex_a53/gnu/xen_build/timer.c
void irqHandler(void)
{
  unsigned int ID;

  ID = getICC_IAR1();

  switch (ID) {
    case VIRTUAL_TIMER_IRQ:
      handle_vtimer_interrupt();
      _tx_timer_interrupt();
      break;

    default:
      // unexpected ID value
      printf("irqHandler() - Unexpected INTID %d\n\n", ID);
      break;
  }

  // finished handling the interrupt
  setICC_EOIR1(ID);
}
```

continue to run, it crashed in `_tx_timer_interrupt()`.

![image](../assets/2024.08/s27.png)

it is an address access error, null pointer.
check the source code, when the vtimer interrupt arrives, global variable `_tx_timer_current_ptr` maybe null.
so add a check:

```diff
ports/cortex_a53/gnu/src/tx_timer_interrupt.s
__tx_timer_no_time_slice:

    /* Test for timer expiration.  */
    // if (*_tx_timer_current_ptr)
    // {

    LDR     x1, =_tx_timer_current_ptr          // Pickup current timer pointer addr
    LDR     x0, [x1, #0]                        // Pickup current timer
+   CMP     x0, #0
+   BEQ     __tx_timer_nothing_expired
    LDR     x2, [x0, #0]                        // Pickup timer list entry
    CMP     x2, #0                              // Is there anything in the list?
    BEQ     __tx_timer_no_timer                 // No, just increment the timer
```

### step 11. supporting dtb

as mentioned before, xen passes hardware information to the VM through the device tree.

in order to support device tree, I involved [dtc](https://github.com/dgibson/dtc) for threadx VM.

```diff
ports/cortex_a53/gnu/CMakeLists.txt
message(STATUS "find libc from ${CMAKE_SOURCE_DIR}")
-target_link_libraries(${CMAKE_SOURCE_DIR}/../libc/build/libc.a)
+target_link_libraries(${EXE_NAME} ${CMAKE_SOURCE_DIR}/../dtc/libfdt/libfdt.a ${CMAKE_SOURCE_DIR}/../libc/build/libc.a)
target_link_libraries(${EXE_NAME} ${PROJECT_NAME})
```

as we known, linux supports xen, so check the documentation of linux:

![image](../assets/2024.08/s28.png)

check the register x0 when booting threadx VM:

![image](../assets/2024.08/s29.png)

modify the code to pass the dtb address into the `main` function.

```diff
ports/cortex_a53/gnu/xen_build/startup.s
el1_entry_aarch64:
+   // save dtb physical address
+   mov x28, x0

    // just check el by manual
    mrs x1, CurrentEL

    // load el1 interrupt vector
    ldr x1, =el1_vectors
    virt_to_phys x1
    msr VBAR_EL1, x1
......
    // Set argc = 1, argv[0] = "" and then call main
    .pushsection .data
    .align 3
argv:
    .dword arg0
    .dword 0
arg0:
    .byte 0
    .popsection

+   ldr x0, =argv
+   add x0, x0, #8
+   str x28, [x0]

-   mov x0, #1
+   mov x0, #2
    ldr x1, =argv
    bl main

ports/cortex_a53/gnu/xen_build/main.c
int main(int argc, char *argv[])
{
+   void *device_tree;

    HYPERVISOR_console_io(CONSOLEIO_write, 8, "threadx\n");

+   printf("main argc %d, argv %p\n", argc, argv[1]);

+   device_tree = argv[1];
+   if (fdt_check_header(device_tree)) {
+       printf("invalid dtb from xen\n");
+   }
```

after modification, run and check the console information:

![image](../assets/2024.08/s30.png)

of course, it crashed because dtb address 0x43e00000 cannot be accessed in `main`.

![image](../assets/2024.08/s31.png)

by reviewing the `startup.s` code before the `main` function, it can be seen that physical to virtual address mapping was performed and the MMU was enabled during startup.
when executing `el1_entry_aarch64`, the dtb address space can be accessed because the MMU is disabled.
the dtb address can not be accessed after the MMU is enabled.

### step 12. map dtb space

in order to access dtb address in `main`, the physical address of dtb address need to be mapped into virtual address space.

in aarch64, the generic address translation process:

![image](../assets/2024.08/s32.png)

TCR_EL1 (Translation Control Register for Exception Level 1) is a system register in ARM architecture that controls memory translation settings, including page size, address ranges, and translation table base configuration for the EL1 exception level.

![image](../assets/2024.08/s33.png)

first take a look at the current implementation, the TCR_EL1 register is set to 0x00000000 00802520.

```text
ports/cortex_a53/gnu/xen_build/startup.s
    ldr x1, =0x0000000000802520
    msr TCR_EL1, x1
    isb
```

because TCR_EL1.DS is 0, so the OA (output address) is 48 bits.

![image](../assets/2024.08/s34.png)

the format of the corresponding page table is as follows:

![image](../assets/2024.08/s35.png)

therefore, the last two bits can only be b01 or b11, which indicate that the next level is either a block address (i.e., a large memory address) or a page table, respectively.
In `startup.s`, it is always set to b11:

```text
ports/cortex_a53/gnu/xen_build/startup.s
    // Get the start address of RAM (the EXEC region) into x4
    // and calculate the offset into the L1 table (1GB per region,
    // max 4GB)
    //
    // x23 = L1 table offset, saved for later comparison against
    //       peripheral offset
    //
    ldr x4, =__code_start
    ubfx x23, x4, #30, #2

    orr x1, x22, #TT_S1_ATTR_PAGE
    str x1, [x21, x23, lsl #3]
```

register x23 holds the bits 30 to 38 of the ram start address, therefore it is the index of the level 1 page table.

prepare dtb level 2 page table, virtual address space for dtb from xen, and map it.

```diff
ports/cortex_a53/gnu/xen_build/threadx.ld
+    .dtb 0x8000000 (NOLOAD) : {
+        dtb = .;
+        . = . + 0x10000;
+    }
......
+    .ttb0_l2_dtb (NOLOAD) : {
+        . = ALIGN(4096);
+        __ttb0_l2_dtb = .;
+        . = . + 0x1000;
+    }

ports/cortex_a53/gnu/xen_build/startup.s
+    //** map dtb address space **
+    ldr x22, =__ttb0_l2_dtb
+    virt_to_phys x22
+    mov x1, #(512 << 3)
+    mov x0, x22
+    bl ZeroBlock
+    ldr x4, =dtb // this is virtual address
+    ubfx x23, x4, #30, #2
+    ubfx x24, x4, #21, #9
+    // update level 1 table
+    orr x1, x22, #TT_S1_ATTR_TABLE
+    ldr x0, [x21, x23, lsl #3]
+    cmp x0, #0
+    beq use_dtb_l2_table
+    nop
+    // use current level 1 table (__ttb0_l2_ram)
+    lsr x0, x0, #2
+    lsl x0, x0, #2
+    mov x22, x0
+    b update_l2_table
+  use_dtb_l2_table:
+    str x1, [x21, x23, lsl #3]
+  update_l2_table:
+    // 2M for dtb is enough
+    mov x4, x28
+    bic x4, x4, #((1 << 21) - 1)
+    ldr x1, =(TT_S1_ATTR_BLOCK | \
+             (1 << TT_S1_ATTR_MATTR_LSB) | \
+              TT_S1_ATTR_NS | \
+              TT_S1_ATTR_AP_RW_PL1 | \
+              TT_S1_ATTR_SH_INNER | \
+              TT_S1_ATTR_AF | \
+              TT_S1_ATTR_nG)
+    orr x1, x1, x4
+    // x0 = address of level 2 table
+    add x0, x22, x24, lsl #3
+    str x1, [x0]
```

notice, here the memory type is `(1 << TT_S1_ATTR_MATTR_LSB)`.

different types of software have different memory requirements.
e.g., frame buffer memory is typically large (a few megabytes) and is usually written more than it is read by the processor.
using strong ordered memory for a frame buffer generates very large amounts of bus traffic, because operations on the entire buffer are implemented using partial writes rather than line writes.
therefore, systems should use write-combining memory for frame buffers whenever possible.

the ARM64 architecture uses different memory types, such as normal, device, and strongly-ordered, which control how memory accesses are handled.
The MAIR_EL1 (Memory Attribute Indirection Register for EL1) is used to configure memory attributes for these types, mapping memory regions to their corresponding attributes, such as cacheability and access order.

in `startup.s`, there are 3 memory types are set when booting.

```text
ports/cortex_a53/gnu/xen_build/startup.s
    //
    // Set up memory attributes
    //
    // These equate to:
    //
    // 0 -> 0b01000100 = 0x00000044 = Normal, Inner/Outer Non-Cacheable
    // 1 -> 0b11111111 = 0x0000ff00 = Normal, Inner/Outer WriteBack Read/Write Allocate
    // 2 -> 0b00000100 = 0x00040000 = Device-nGnRE
    //
    mov  x1, #0xff44
    movk x1, #4, LSL #16    // equiv to: movk x1, #0x0000000000040000
    msr MAIR_EL1, x1
```

1 is the index of memory attributes in MAIR_EL1.

pass dtb virtual address to `main`.

```diff
ports/cortex_a53/gnu/xen_build/startup.s
argv:
    .dword arg0
    .dword 0
+   .dword 0
arg0:
    .byte 0
    .popsection

    ldr x0, =argv
    add x0, x0, #8
    str x28, [x0]
+   ldr x1, =dtb
+   add x0, x0, #8
+   str x1, [x0]

-   mov x0, #2
+   mov x0, #3
    ldr x1, =argv
    bl main

ports/cortex_a53/gnu/xen_build/main.c
int main(int argc, char *argv[])
{
    void *device_tree;

    HYPERVISOR_console_io(CONSOLEIO_write, 8, "threadx\n");

-   printf("main argc %d, argv %p\n", argc, argv[1]);
+   printf("main argc %d, argv %p, dtb va %p\n", argc, argv[1], argv[2]);

-   device_tree = argv[1];
+   device_tree = argv[2];
    if (fdt_check_header(device_tree)) {
        printf("invalid dtb from xen\n");
    }
```

now, `fdt_check_header` in `main` returned 0 which means dtb is valid.

### step 13. virtual address

in section [update memory layout of threadx](#step-6-update-memory-layout-of-threadx), note that the virtual addresses and physical addresses are the same in the memory layout.
but it is generally unreasonable to require virtual addresses to be the same as physical addresses.
now fix it.

set the program address to 0x10000000 which is not equal with physical address.

```diff
ports/cortex_a53/gnu/xen_build/threadx.ld
+   . = 0x10000000; /* THREADXEN_VA */
-   . = 0x40000000; /* THREADXEN_VA */
    _threadxen_start = .;
    .pecoff : {
        KEEP(*(.pecoff))
    }
```

it crashed when running. the following is at the beginning of `el1_entry_aarch64`.

```text
ports/cortex_a53/gnu/xen_build/startup.s
    //
    // Now we're in EL1, setup the application stack
    // the scatter file allocates 2^14 bytes per app stack
    //
    ldr x0, =__handler_stack
    virt_to_phys x0
    sub x0, x0, x19, lsl #14
    mov sp, x0
    MSR     SPSel, #0
    ISB
    ldr x0, =__stack
    virt_to_phys x0
    sub x0, x0, x19, lsl #14
    mov sp, x0
```

the stack loaded here is a virtual address, but the MMU has not been initialized at this point.
therefore, when executing the `bl` function, a memory access error is inevitable.

implement a macro to convert virtual addresses to physical addresses:

```diff
ports/cortex_a53/gnu/xen_build/startup.s
+// x27 = offset of pa & va
+.macro virt_to_phys va
+	add \va, \va, x27
+.endm

// ------------------------------------------------------------
// EL1 - Common start-up code
// ------------------------------------------------------------

    .global el1_entry_aarch64
    .type el1_entry_aarch64, "function"
el1_entry_aarch64:
+   // calculate offset of pa & va
+   adr x27, el1_entry_aarch64
+   ldr x28, =el1_entry_aarch64
+   sub x27, x27, x28

    // save dtb physical address
    mov x28, x0

    // just check el by manual
    mrs x1, CurrentEL

    // load el1 interrupt vector
    ldr x1, =el1_vectors
+   virt_to_phys x1
    msr VBAR_EL1, x1

    //
    // Now we're in EL1, setup the application stack
    // the scatter file allocates 2^14 bytes per app stack
    //
    ldr x0, =__handler_stack
+   virt_to_phys x0
    sub x0, x0, x19, lsl #14
    mov sp, x0
    MSR     SPSel, #0
    ISB
    ldr x0, =__stack
+   virt_to_phys x0
    sub x0, x0, x19, lsl #14
    mov sp, x0
```

after the modification, it crashes after enabling the MMU in the `startup.s`, instructions at physical addresses cannot be accessed, but virtual addresses can be accessed.

![image](../assets/2024.08/s36.png)

how to solve this problem?
add a new mapping relationship: the virtual address equals the physical address, meaning that one physical address space is mapped to two virtual address spaces.

![image](../assets/2024.08/s37.png)

after the dual mapping, the instructions can execute normally after enabling the MMU:

![image](../assets/2024.08/s38.png)

in addition, after enabling the MMU, the stack also needs to be reconfigured, ensuring that the stack is set using virtual addresses at this time.

```diff
ports/cortex_a53/gnu/xen_build/startup.s
    // Enable the MMU.  Caches will be enabled later, after scatterloading.
    //
    mrs x1, SCTLR_EL1
    orr x1, x1, #SCTLR_ELx_M
    bic x1, x1, #SCTLR_ELx_A // Disable alignment fault checking.  To enable, change bic to orr
    msr SCTLR_EL1, x1
    isb

+   // jump to VA space & flush pipeline
+   ldr x0, =va_space
+   br x0
+ va_space:
+   // ** set stack pointer with VA
+   ldr x0, =__handler_stack
+   sub x0, x0, x19, lsl #14
+   mov sp, x0
+   MSR     SPSel, #0
+   ISB
+   ldr x0, =__stack
+   sub x0, x0, x19, lsl #14
+   mov sp, x0
```

here, the program addresses in threadx are decoupled from the physical addresses allocated by xen.

### step 14. mmap

next, decouple the peripheral address space, as the peripheral addresses were previously hardcoded in `threadx.ld`.
in reality, xen passes the allocated physical addresses (which are actually IPA) of the peripherals to the VM through the device tree.

implement one function `mmap_dev` to convert device io addresses to virtual addresses:

```diff
ports/cortex_a53/gnu/xen_build/mmap.c
+#define update_l2_block(t, va, pa) \
+    do { \
+        uint64_t *tab = t; \
+        *(tab + (((va) >> 21) & 0x1ff)) = ((pa) & (~0x1fffff)) | (TT_S1_ATTR_BLOCK | (2 << TT_S1_ATTR_MATTR_LSB) | TT_S1_ATTR_NS | TT_S1_ATTR_AP_RW_PL1 | TT_S1_ATTR_AF | TT_S1_ATTR_nG); \
+    } while (0)
+
+#define get_l2_item(t, va) *((uint64_t *)(t) + (((va) >> 21) & 0x1ff))
+
+#define get_l1_item(t, va) *((uint64_t *)(t) + (((va) >> 30) & 0xf))
+
+void mmap_dev(uint64_t va, uint64_t pa, size_t size)
+{
+    uint64_t *tab1 = (uint64_t *) &__ttb0_l1;
+    uint64_t *tab2 = (uint64_t *) &__ttb0_l2_periph;
+
+    // check item of table level 1
+    if (0 == get_l1_item(tab1, va)) {
+        // level 2
+        update_l2_block(tab2, va, pa);
+        __asm__ __volatile__("dsb ish");
+
+        // level 1
+        get_l1_item(tab1, va) = (uint64_t) virt_to_phys(tab2) | TT_S1_ATTR_TABLE;
+        __asm__ __volatile__("dsb ish");
+    } else {
+        // level 2, notice tab2 is get from tab1, so tab2 is physical address
+        tab2 = (uint64_t *)(get_l1_item(tab1, va) & (~0xfff));
+        // we could access physcial address beacause of shadow map
+        for (size_t i = 0; i < size; i += L2_BLOCK_ADDR_SIZE) {
+            update_l2_block(tab2, va + i, pa + i);
+        }
+        __asm__ __volatile__("dsb ish");
+    }
+
+    // flush tlb
+    __asm__ __volatile__("tlbi VMALLE1\n\t"
+                         "ic iallu\n\t" /* flush I-cache */
+                         "dsb sy\n\t" /* ensure completion of TLB flush */
+                         "isb");
+}
```

notice, here memory type is index 2 `(2 << TT_S1_ATTR_MATTR_LSB)` in MAIR_EL1 which means it is device memory type.

the function `mmap_dev` has a flaw in that the mapping granularity is 2M. if finer granularity is required, such as a 4K mapping, then a level 3 page table must be used.

but if a level 3 page table is used, memory space must be prepared for the page tables.
e.g., the occupied GIC address space is 0x1000000 (which doesn’t consume actual memory, as it is MMIO space).
the number of required page tables is 0x1000000 / 2M = 8. the memory required for level 3 page tables would be 8 * 4K.

![image](../assets/2024.08/s39.png)

but 8 * 4K is too expensive for a system like threadx, especially considering that it has only allocated 64M of memory to this VM.

![image](../assets/2024.08/s40.png)

so abandoning the level 3 page table approach, just map peripherals in the level 2 page table.
for most embedded chips, the peripheral address space is generally arranged in a contiguous manner during the chip design.

here, the hardcoded physical address of gicd & gicr could be removed.
GIC physical address could be read from dtb and then map to virtual address.

### step 15. example threads

last, add some print in example threads and call threadx api `tx_kernel_enter` in `main`.

```c
int main(int argc, char *argv[])
{
    void *device_tree;

    HYPERVISOR_console_io(CONSOLEIO_write, 8, "threadx\n");

    printf("main argc %d, argv %p, dtb va %p\n", argc, argv[1], argv[2]);

    device_tree = argv[2];
    if (fdt_check_header(device_tree)) {
        printf("invalid dtb from xen\n");
    }

    /* initialize interrupt controller */
    setup_gic(device_tree);

    /* initialize timer.  */
    init_timer(device_tree);

    /* Enter ThreadX.  */
    tx_kernel_enter();

    return 0;
}
......
void thread_0_entry(ULONG thread_input)
{
    UINT status;

    /* This thread simply sits in while-forever-sleep loop.  */
    while(1) {
        printf("thread 0\n");
```

all example threads work!

## conclusion

nothing

## references

Arm Generic Interrupt Controller v3 and v4 Overview

AArch64 Programmer's Guides - Generic Timer

## future
enable smp for threadx

guix
