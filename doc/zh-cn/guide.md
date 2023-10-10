# Guide

## KernelPatch 是如何做到的

KernelPatch 包含 kptools kpimg kpatch 三个部分

### [kptools](/tools/)

kptools 主要有以下几个作用：

- 可以在无源码和符号信息的情况下解析内核镜像，获取任意内核符号的偏移地址。
- 修补内核镜像，将 kpimg 追加到内核镜像后面并将一些必要的信息写入到 kpimg 预设的位置上，最后内核的启动位置替换为kpimg起始地址。

### [kpimg](/kernel/)

- kpimg 是一个经过特殊设计的 ELF。  
- kpimg 会接管内核启动，并完成所有的内核动态修补工作，并将功能以系统的调用的形式倒出供用户使用。  
- 如果你不需要太多的功能，或者想要定制的话，[kernel/base](/kernel/base) 代码可以单独拿出来使用。  

- [SuperCall](./super-syscall.md)

- [Kernel Inline Hook](./inline-hook.md)

- [Kernel Patch Module](./module.md)

### [kpuser](/user/)

kpuser 是用户空间头文件，库，还有一个可执行程序 kpatch，可以直接将它们嵌入到你的程序中。
