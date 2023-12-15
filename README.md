# KernelPatch

**Patching and hooking the Linux kernel with only stripped Linux kernel image.**

``` shell
 _  __                    _ ____       _       _     
| |/ /___ _ __ _ __   ___| |  _ \ __ _| |_ ___| |__  
| ' // _ \ '__| '_ \ / _ \ | |_) / _` | __/ __| '_ \ 
| . \  __/ |  | | | |  __/ |  __/ (_| | || (__| | | |
|_|\_\___|_|  |_| |_|\___|_|_|   \__,_|\__\___|_| |_|

```

If you are using Android, [APatch](https://github.com/bmax121/APatch) would be a better choice.

KernelPatch provides the fundamental capability to parse Linux kernel images without source code and symbol information, allowing for the retrieval of arbitrary symbol offsets and the injection of arbitrary code into the kernel.  
Building upon this foundation, KernelPatch offers essential features such as system-call-hook and inline-hook in the kernel.  
You have complete control over the kernel, allowing you to implement desired functionalities such as privilege escalation, hiding, monitoring, and more.  

## Supported Versions

Currently only supports arm64 architecture.  

Linux 3.18 - 6.2 (theoretically)  
Linux 6.3+ (not yet adapted)  

## Get Help

## Get Involved

## Community Discussion

## More Information

[Documentation](./doc/en/)

## Credits

- [vmlinux-to-elf](https://github.com/marin-m/vmlinux-to-elf): Some ideas for parsing kernel symbols.
- [android-inline-hook](https://github.com/bytedance/android-inline-hook): Some code for fixing arm64 inline hook instructions.
- [KernelSU](https://github.com/tiann/KernelSU): Some Android compat code.
- [tlsf](https://github.com/mattconte/tlsf): Memory allocator used for KPM. (Need a better one to allocate ROX memory.)

## License

KernelPatch is licensed under the **GNU General Public License (GPL) 2.0** (<https://www.gnu.org/licenses/old-licenses/gpl-2.0.html>).
