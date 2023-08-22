# Guide

## KernelPatch 是如何做到的

KernelPatch 包含 kptools kpimg kpatch 三个部分

### [kptools](/tools/)

kptools 主要有以下几个作用：

- 可以在无源码和符号信息的情况下解析内核镜像，获取任意内核符号的偏移地址。
- 修补内核镜像，将 kpimg 追加到内核镜像后面并将一些必要的信息写入到 kpimg 预设的位置上，最后内核的启动位置替换为kpimg起始地址。

### [kpimg](/kernel/)

kpimg 是一个经过特殊设计的 ELF

1. kpimg 接管内核启动，此时内核还在使用物理地址，kpimg 会在这时将必要的信息写入到 [map](/kernel/base/map.c) 和 [start](/kernel/base/start.c)，
然后将其都重定位到指定的位置
2. 替换 **paging_init** 为 **_paging_init**，然后重新启动内核
3. **_paging_init** 预留空间，修改页表属性，然后跳转到 **start**
4. **start** 阶段会进一步修改页表，初始化内核内联钩子等，然后进入到 **init**
5. **init** 是一个相对舒服的C语言世界（除了静态链接的绝对地址），在这里我们可以完成任意我们想要的功能，例如修改系统调用，等。  

如果你不需要太多的功能，或者想要定制的话，[/kernel/base](/kernel/base) 代码可以单独拿出来使用。  

- [SuperCall](./super-syscall.md)

- [Kernel Inline Hook](./inline-hook.md)

- [Kernel Patch Module](./module.md)

### [kpuser](/user/)

kpuser 是用户空间头文件，库，还有一个可执行程序 kpatch，可以直接将它们嵌入到你的程序中。
