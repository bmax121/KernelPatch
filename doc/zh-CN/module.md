# KernelPatch Module

## 什么是 KernelPatch Module (KPM)

  **KPM 是一个 ELF 文件可以由KernelPatch在内核空间中加载和运行.**  

## 如何写一个 KPM

  以下是一些你可以用来快速理解的例子。

1. 一个简单的 hello world KPM: [hello-world](/kpm-demo/hello)  
2. 如何通过KPM实现内核函数内联挂钩: [inline-hook](/kpm-demo/inlinehook)  
3. 如何 hook 系统调用通过 KPM: [syscallhook](/kpm-demo/syscallhook)  

### 在没有内核源码树的情况下工作

### 使用内核源码树工作
