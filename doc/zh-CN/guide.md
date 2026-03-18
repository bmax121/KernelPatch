# 概述

## KernelPatch 工作原理

KernelPatch 由三个组件组成：kptools、kpimg 和 kpatch。

### [kptools](/tools/)

kptools 的功能：

- 无需内核源码或符号信息，即可解析内核镜像并获取任意内核符号的偏移地址。
- 将 kpimg 附加到内核镜像末尾，向 kpimg 中的预设位置写入必要信息，最后将内核启动入口替换为 kpimg 的起始地址，完成镜像修补。

### [kpimg](/kernel/)

- kpimg 是一个专门设计的 ELF 文件。
- kpimg 接管内核启动流程，完成所有内核动态修补，并通过系统调用向用户层导出功能。
- 如果不需要完整功能或希望自定义，可以单独使用 [kernel/base](/kernel/base) 中的代码。

- [SuperCall](./super-syscall.md)

- [内核 Inline Hook](./inline-hook.md)

- [内核修补模块](./module.md)

### [kpuser](/user/)

kpuser 是 KernelPatch 的用户空间头文件与库，可以直接嵌入到你的程序中使用。
