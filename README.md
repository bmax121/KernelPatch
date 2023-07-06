# KernelPatch

**Patching and hooking the Linux kernel with only stripped Linux kernel image.**

If you are using Android, [AndroidKernelPatch](https://github.com/bmax121/AndroidKernelPatch) would be a better choice.

**English** | [简体中文](README_zh-CN.md)

KernelPatch provides the fundamental capability to parse Linux kernel images without source code and symbol information, allowing for the retrieval of arbitrary symbol offsets and the injection of arbitrary code into the kernel.  
Building upon this foundation, KernelPatch offers essential features such as system-call-hook and inline-hook in the kernel.  
You have complete control over the kernel, allowing you to implement desired functionalities such as privilege escalation, hiding, monitoring, and more.  

**KernelPatch is intended solely for learning and communication purposes. It is strictly prohibited from being used for any illegal activities.**

## Supported Versions

Currently only supports arm64 architecture.  

Linux 3.8 - 6.2 (theoretically)  
Linux 6.3+ (not yet adapted)  
Linux 4.4, 4.20, 5.10 (tested)  
Pixel2xl-Android10, Linux 4.4.210 (tested)  
Pixel3xl-Android12, Linux 4.9.270 (tested)  
Pixel4xl-Android13, Linux 4.14.276 (tested)  
Oneplus8T-Android13, Linux 4.19.157 (tested)  

## Get Help

## Get Involved

## Community Discussion

## More Information

[Documentation](./doc/en/)

## Credits

- [vmlinux-to-elf](https://github.com/marin-m/vmlinux-to-elf): Some ideas for parsing kernel symbols.
- [android-inline-hook](https://github.com/bytedance/android-inline-hook): Some code for fixing arm64 inline hook instructions.
- [https://elixir.bootlin.com](https://elixir.bootlin.com/linux/v6.2.16/C/ident/): Linux source code online.

## License

KernelPatch is licensed under the **GNU General Public License v3 (GPL-3)** (<http://www.gnu.org/copyleft/gpl.html>).
