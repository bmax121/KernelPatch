# KernelPatch Module

## 什么是 KernelPatch Module (KPM)

  **KPM is an ELF file that can be loaded and run within the kernel space by KernelPatch.**  

  KPM in principle and implementation is quite similar to LKM. There is no doubt about this, as much of the implementation code in KPM is derived from LKM. However, this does not imply a seamless transition from LKM to KPM, as there may be numerous compatibility issues.  

  **The design purpose of KPM is not to replace LKM; rather, KPM is intended to accomplish specific, small, and elegant tasks, such as monitoring and hiding. Of course, if you want to develop a complex module, you can do that too.**  

## How to write a KPM

  Here are a few examples that you can use to quickly understand.  

1. A simple hello world KPM: [hello-world](/kpm-demo/hello)  
2. How to do kernel function inline-hook via KPM: [inline-hook](/kpm-demo/inlinehook)  
3. How to hook system call via KPM: [syscallhook](/kpm-demo/syscallhook)  

### Working without Kernel source tree

### Working with Kernel soruce tree
