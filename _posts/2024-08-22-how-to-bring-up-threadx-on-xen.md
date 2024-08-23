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

all the reference implementation: https://github.com/tw-embedded/baize-board

## whole architecture
![architecture image](../assets/2024.08/picture1.png)

## all steps

## conclusion

## future
enable smp for threadx

guix

