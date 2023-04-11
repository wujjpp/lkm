# Makefile 4.0
obj-m := k_netlink.o
CURRENT_PATH := $(shell pwd)
LINUX_KERNEL := $(shell uname -r)
LINUX_KERNEL_PATH := /usr/src/kernels/$(LINUX_KERNEL)

install:
	insmod k_netlink.ko

uninstall:
	rmmod k_netlink.ko