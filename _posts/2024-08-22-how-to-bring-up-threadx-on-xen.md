---
title: "how to bring up threadx on xen (writing)"
date: 2024-08-22
categories: [blog, embedded]
tags: [threadx, xen]
---

## what are xen & threadx?
[xen](https://xenproject.org) is a type-I hypervisor, [threadx](https://threadx.io) is a RTOS.

## why we need virtualization?
in many industries, it is necessary to be able to run different operating systems (or even no operating system at all) to meet various business requirements. multiple OS could be run without hypervisor. however, the system mostly restart if one core crashed. the embedded field has extremely high requirements for stability, and virtualization can enhance stability.

others include, resource efficiency, isolation and security, scalability and flexibility, and so on.

## why xen & threadx?
QNX is primarily used in the automotive sector and is a closed-source operating system.

## prerequisites
in the development environment, I used QEMU to emulate one board, and the board's SoC adopts an ARM multi-core processor. using QEMU is flexible, low-cost, convenient for debugging (the most important aspect), and easy to promote (users don't need to purchase a development board).

all the reference implementation: <https://github.com/tw-embedded/baize-board>

## whole architecture
![architecture image](../assets/2024.08/picture1.png)

Exception Levels (EL): hierarchical privilege levels in ARM architecture. it determines the amount of control and access a process or code running at a particular level has. there are four levels, from EL0 to EL3, each with different levels of privilege:

EL0: the lowest privilege level, typically used for user applications.

EL1: used for operating system kernels and drivers.

EL2: used for hypervisors in virtualization scenarios.

EL3: the highest privilege level, usually for secure monitor code and system management.

## all steps

### step 1. build threadx project

after cloning the project repository, create a new build folder for porting to xen:

```bash
cp -r ./ports/cortex_a53/gnu/example_build/sample_threadx ./ports/cortex_a53/gnu/xen_build
```

yes, here i selected cortex a53 as target. added several cmake files:

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
+set(LD_FLAGS "-nostartfiles")
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

here, i have allocated one CPU for threadx, which means that threadx does not need to support SMP for the time being.
the memory available to threadx is very limited, with only 0x10000 bytes.
additionally, threadx is being booted in a typical dom0-less configuration.

### step 3. boot threadx

as expected, the boot failed.

![boot image](../assets/2024.08/s1.png)

review the most recent non-failing logs and trace them back to the corresponding code。

```text
(XEN) *** LOADING DOMU cpus=1 memory=10000KB ***
(XEN) Loading d1 kernel from boot module @ 0000000127aaa000
```

it is in the `kernel_probe` function.

![boot image](../assets/2024.08/s2.png)

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

first, `kernel_zimage64_probe` checks the magic number, the macros are defined:

```c
#define ZIMAGE64_MAGIC_V0 0x14000008
#define ZIMAGE64_MAGIC_V1 0x644d5241 /* "ARM\x64" */
```

## conclusion

## future
enable smp for threadx

guix
