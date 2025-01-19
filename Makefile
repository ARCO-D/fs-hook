KDIR := /home/kirin7/kernel/linux-6.6.57
CC = aarch64-arco-linux-gnu-gcc
ccflags-y := -Wno-error
obj-m=test1.o test2.o
PWD=$(shell pwd)

all:
	make -C $(KDIR) M=$(PWD) modules
	md5sum test*.ko

clean:
	make -C $(KDIR) M=$(PWD) clean
