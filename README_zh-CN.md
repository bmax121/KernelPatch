# KernelPatch

**Patching and hooking the Linux kernel with only stripped Linux kernel image.**

``` shell
 _  __                    _ ____       _       _     
| |/ /___ _ __ _ __   ___| |  _ \ __ _| |_ ___| |__  
| ' // _ \ '__| '_ \ / _ \ | |_) / _` | __/ __| '_ \ 
| . \  __/ |  | | | |  __/ |  __/ (_| | || (__| | | |
|_|\_\___|_|  |_| |_|\___|_|_|   \__,_|\__\___|_| |_|

```

如果你在使用 Android，[AndroidKernelPatch](https://github.com/bmax121/AndroidKernelPatch) 会是更好的选择。

KernelPatch 提供可以在无源码无符号情况下解析Linux内核镜像，获取任意符号偏移，并向内核中注入任意代码的基础能力。  
在此基础上，KernelPatch 还提供了系统调用 hook，内核 inline-hook 等基础功能。  
你可以完全的掌控内核，实现你想要的功能，比如提权，隐藏，监控等等。  

## 支持情况

当前只支持 arm64

Linux 3.18 - 6.2 (理论上)  
Linux 6.3+ (暂未适配)  

## 获取帮助

## 参与进来

## 讨论

## 更多信息

[文档](./doc/zh-cn/)

## 鸣谢

- [vmlinux-to-elf](https://github.com/marin-m/vmlinux-to-elf): 参考学习了解析内核符号的思路
- [android-inline-hook](https://github.com/bytedance/android-inline-hook): 用了 arm64 inline hook 指令修复的代码

## 许可证

KernelPatch 发布许可：**GNU General Public License (GPL) 2.0** (<https://www.gnu.org/licenses/old-licenses/gpl-2.0.html>).
