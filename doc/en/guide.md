# Guide

## How KernelPatch Works

KernelPatch consists of three components: kptools, kpimg, and kpatch.

### [kptools](/tools/)

kptools serves the following purposes:

- It can parse kernel images without source code or symbol information and retrieve the offset addresses of arbitrary kernel symbols.
- It patches the kernel image by appending kpimg to the end of the image and writing necessary information to the predetermined locations in kpimg. Finally, it replaces the kernel's startup location with the starting address of kpimg.

### [kpimg](/kernel/)

kpimg is a specially designed ELF that performs further patching of the kernel after taking over the kernel startup. It relocates its own data and code, modifies page tables, allocates space, initializes kernel inline hooks, and more. This is the core of KernelPatch. If you don't need additional features or want to patch the kernel yourself, you can use the code in this part separately.  

After that, we enter a relatively comfortable C language world (where almost all C code can be used, except for absolute addresses determined during static linking). Here, we further patch permission management, modify system calls, export desired functionalities, and complete KPM initialization (todo), etc.

- [SuperCall](./super-syscall.md)

- [Kernel Inline Hook](./inline-hook.md)

- [Kernel Patch Module](./module.md)

### [kpuser](/user/)

kpuser is the user space header file and static library for KernelPatch. You can directly embed kpatch into your program.
