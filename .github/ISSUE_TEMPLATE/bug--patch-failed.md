---
name: 'Bug: Patch Failed'
about: kptools fails to patch kernel image
title: 'Patch Failed (Device Name) (Device Kerenl Version) '
labels: ''
assignees: bmax121

---

**First, confirm whether your kernel has CONFIG_KALLSYMS_ALL=y enabled. If not or cannot be sure, please wait for support.**

The following two information are what I need to fix the problem

1. Your boot.img or kernel image

Upload to here or file download path

2.  The real symbol informations corresponding to your boot.img or kernel
It can be obtained through the following two commands under **root**.
```shell
echo 1 > /proc/sys/kernel/kptr_restrict
cat /proc/kallsyms
```

Upload to here or file download path
