---
title: "how to bring up threadx on xen"
date: 2024-08-22
categories: [blog, embedded]
tags: [threadx, xen]
---

# still writing ...

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
### step 1: build threadx project
after cloning the project repository, create a new build folder for porting to xen:

```bash
cp -r ./ports/cortex_a53/gnu/example_build ./ports/cortex_a53/gnu/xen_build
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
```

execute the following commands to build threadx:

```bash
cmake -Bbuild -GNinja -DCMAKE_TOOLCHAIN_FILE=cmake/cortex_a53.cmake
cmake --build ./build
```

## conclusion

## future
enable smp for threadx

guix
