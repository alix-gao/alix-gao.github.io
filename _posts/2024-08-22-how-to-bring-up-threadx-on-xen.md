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

yes, here i selected cortex a53 as target. add several cmake files:

```diff
cmake/aarch64-linux-gnu.cmake
cmake/cortex_a53.cmake
ports/cortex_a53/gnu/CMakeLists.txt
```

(for detailed information, please refer to <https://github.com/tw-embedded/threadx/commit/4799a3ebcb08bb2d56d5cf94e6627a836e0adf8a>)

execute the following commands to build threadx:

```bash
cmake -Bbuild -GNinja -DCMAKE_TOOLCHAIN_FILE=cmake/cortex_a53.cmake
cmake --build ./build
```

## conclusion

## future
enable smp for threadx

guix
