# KernelPatch

KernelPatch 提供可以在无源码无符号情况下解析Linux内核镜像，获取任意符号偏移，并向内核中注入任意代码的基础能力。  
在此基础上，KernelPatch 还提供了系统调用 hook，内核 inline-hook 等基础功能。  
你可以完全的掌控内核，实现你想要的功能，比如提权，隐藏，监控等等。  

**KernelPatch 仅供学习交流。严禁用于任何非法用途。**

## 支持情况

当前只支持 arm64

Linux 3.8 - 6.2 (理论上)  
Linux 6.3+ (暂未适配)  
Linux 4.4, 4.20, 5.10 (测试过)  
Pixel2xl-Android10, Linux 4.4.210 (测试过)  
Pixel3xl-Android12, Linux 4.9.270 (测试过)  
Pixel4xl-Android13, Linux 4.14.276 (测试过)  
Oneplus8T-Android13, Linux 4.19.157 (测试过)  

## 获取帮助

## 参与进来

## 讨论

## 更多信息

[文档](./doc/zh-cn/)

## 鸣谢

- [vmlinux-to-elf](https://github.com/marin-m/vmlinux-to-elf): 参考学习了解析内核符号的思路
- [android-inline-hook](https://github.com/bytedance/android-inline-hook): 用了 arm64 inline hook 指令修复的代码
- [linux source code online](https://elixir.bootlin.com/linux/v6.2.16/C/ident/): 内核源码在线

## 许可证

KernelPatch 发布许可：**GNU General Public License v3 (GPL-3)** (<http://www.gnu.org/copyleft/gpl.html>).
