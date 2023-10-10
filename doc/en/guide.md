# Guide

## How KernelPatch Works

KernelPatch consists of three components: kptools, kpimg, and kpatch.

### [kptools](/tools/)

kptools serves the following purposes:

- It can parse kernel images without source code or symbol information and retrieve the offset addresses of arbitrary kernel symbols.
- It patches the kernel image by appending kpimg to the end of the image and writing necessary information to the predetermined locations in kpimg. Finally, it replaces the kernel's startup location with the starting address of kpimg.

### [kpimg](/kernel/)

- kpimg is a specially designed ELF.  
- kpimg takes over the kernel boot process, performs all kernel dynamic patching, and exports functionality for user use via system calls.  
- If you don't need extensive functionalities or want customization, you can separately utilize the code in [kernel/base](/kernel/base).

- [SuperCall](./super-syscall.md)

- [Kernel Inline Hook](./inline-hook.md)

- [Kernel Patch Module](./module.md)

### [kpuser](/user/)

kpuser is the user space header file and library for KernelPatch. You can directly embed kpuser into your program.
