# Guide

## KernelPatch 是如何做到的

KernelPatch 包含 kptools kpimg kpatch 三个部分

### [kptools](/tools/)

kptools 主要有以下几个作用：

- 可以在无源码和符号信息的情况下解析内核镜像，获取任意内核符号偏移的偏移地址。
- 修补内核镜像，将 kpimg 追加到内核镜像后面并将一些必要的信息写入到 kpimg 预设的位置上，最后内核的启动位置替换为kpimg起始地址。

### [kpimg](/kernel/)

kpimg 是一个经过特殊设计的 ELF，在它接管内核启动之后会对内核做进一步的修补，重定位自己的数据与代码，修改页表，开辟空间，初始化内核内联钩子等。
这是 KernelPatch 的核心，如果你不需要更多的功能或者想要自己修补内核，这一部分的[代码](/kernel/base)可以单独拿出来使用。  

随后就进入到一个相对舒服的C语言世界（基本上所有C代码都可以使用，除了静态链接时就要确定的绝对地址），在这里，我们会进一步修补权限管理，修改系统调用，导出我们想要的功能，完成 KPM 初始化（todo）等。  

- [SuperCall](./super-syscall.md)

- [Kernel Inline Hook](./inline-hook.md)

- [Kernel Patch Module](./module.md)

### [kpuser](/user/)

kpuser 是 KernelPatch 的用户空间头文件，静态库，你可以直接将 kpatch 嵌入到你的程序中。  
