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

KernelPatch is licensed under the **GNU General Public License (GPL) 2.0** (<https://www.gnu.org/licenses/old-licenses/gpl-2.0.html>).
