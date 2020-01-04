# This Makefile can Compile the kernel linux-3.12.6

MODNAME=pgcache_scan


obj-m:=${MODNAME}.o
${MODNAME}-objs+= kernel.o sysctl.o cache_scan.o

KDIR:=/lib/modules/$(shell uname -r)/build
DEFE = -Wall -g
PWD:=$(shell pwd)
EXTRA_CFLAGS:= -g -Wall -Wmissing-prototypes -Wstrict-prototypes 
ADDR=$(shell grep -w  kallsyms_lookup_name /proc/kallsyms)

all:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules
#	strip --strip-debug *.ko
load:
	@for i in $(ADDR); \
	do \
		insmod $(MODNAME).ko kallsyms_lookup_name_addr=0x$$i; \
		echo insmod $(MODNAME); \
		break; \
	done
unload:
	rmmod  ${MODNAME}
reload:
	make unload
	make load
status:
	@lsmod |grep ${MODNAME} 
clean:
	make -C $(KDIR) M=$(PWD) clean
