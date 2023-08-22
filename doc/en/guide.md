# Guide

## How KernelPatch Works

KernelPatch consists of three components: kptools, kpimg, and kpatch.

### [kptools](/tools/)

kptools serves the following purposes:

- It can parse kernel images without source code or symbol information and retrieve the offset addresses of arbitrary kernel symbols.
- It patches the kernel image by appending kpimg to the end of the image and writing necessary information to the predetermined locations in kpimg. Finally, it replaces the kernel's startup location with the starting address of kpimg.

### [kpimg](/kernel/)

kpimg is a specially designed ELF

1. kpimg takes over the kernel start-up while the kernel is still using physical addresses. At this point, kpimg writes necessary information into [map](/kernel/base/map.c) and [start](/kernel/base/start.c), then relocates them to the specified location.
2. It replaces **paging_init** with **_paging_init**, and then restarts the kernel.
**_paging_init** reserves space, modifies page table attributes, and jumps to **start**.
3. In the **start** phase, further page table modifications are performed, kernel inline hooks are initialized, and then it proceeds to **init**.
4. **init** provides a relatively comfortable C-language environment (except for statically linked absolute addresses), where we can accomplish various desired functionalities, such as modifying system calls, and more.  

If you don't need extensive functionalities or want customization, you can separately utilize the code in [/kernel/base](/kernel/base).

- [SuperCall](./super-syscall.md)

- [Kernel Inline Hook](./inline-hook.md)

- [Kernel Patch Module](./module.md)

### [kpuser](/user/)

kpuser is the user space header file and library for KernelPatch. You can directly embed kpuser into your program.
