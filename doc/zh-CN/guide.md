# 向导

## KernelPatch 如何工作

KernelPatch 由三个组件组成: kptools, kpimg, and kpatch.

### [kptools](/tools/)

kptools 有以下用途:

- 它可以在没有源代码或符号信息的情况下解析内核镜像，并检索任意内核符号的偏移地址.
- 它修补内核镜像通过添加 kpimg 到镜像末尾并且写入必要信息到kpimg中的预定位置. 最后, 它替换内核的的启动位置为kpimg的起始地址.

### [kpimg](/kernel/)

- kpimg 是特殊设计的ELF.  
- kpimg 接管内核启动过程, 为所有的内核执行动态修补, 并且通过系统调用导出功能为用户使用.  
- 如果你不需要太多的功能或者想要自定义, 你可以分离[kernel/base](/kernel/base)中的代码使用.

- [SuperCall](./super-syscall.md)

- [Kernel Inline Hook](./inline-hook.md)

- [Kernel Patch Module](./module.md)

### [kpuser](/user/)

kpuser 是用户空间的头文件和库用于KernelPatch. 你可以直接把kpuser嵌入到你的程序.
