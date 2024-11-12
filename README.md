# fs hook demo
build on linux-6.6 gcc 7.5, run on arco-qemu/arco-virt

linux6内核不再默认导出kallsyms_lookup_name函数, 且新增了p4d四级页目录项

本demo执行了一个简单的文件系统hook, 替换掉/home目录所属文件系统的iterate_shared回调, 替换成了一个空的函数, 卸载时恢复
