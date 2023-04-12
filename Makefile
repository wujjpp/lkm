CURRENT_PATH := $(shell pwd)
LINUX_KERNEL := $(shell uname -r)
LINUX_KERNEL_PATH := /usr/src/kernels/$(LINUX_KERNEL)

all:
	make -C $(LINUX_KERNEL_PATH) M=$(CURRENT_PATH)/kernel modules
	make -C $(CURRENT_PATH)/user build
	make -C $(CURRENT_PATH)/capture build
	make -C $(CURRENT_PATH)/kb build
	make -C $(CURRENT_PATH)/send build

install:
	make -C $(CURRENT_PATH)/kernel install

uninstall:
	make -C $(CURRENT_PATH)/kernel uninstall

run:
	./user/u_netlink

clean:
	make -C $(LINUX_KERNEL_PATH) M=$(CURRENT_PATH)/kernel clean
	make -C $(CURRENT_PATH)/user clean
	make -C $(CURRENT_PATH)/capture clean
	make -C $(CURRENT_PATH)/kb clean
	make -C $(CURRENT_PATH)/send clean