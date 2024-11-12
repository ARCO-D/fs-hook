KDIR := /home/kirin7/kernel/linux-6.6.57
CC = aarch64-kirin7-linux-gnu-gcc
ccflags-y := -Wno-error
obj-m=hook_test.o
PWD=$(shell pwd)

all:
	make -C $(KDIR) M=$(PWD) modules
	md5sum hook_test.ko

clean:
	make -C $(KDIR) M=$(PWD) clean
