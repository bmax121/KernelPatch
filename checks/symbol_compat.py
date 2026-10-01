#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Cross-version KPM symbol compatibility gate.

Usage: symbol_compat.py [extra.kpm dirs...]

Fails when a symbol referenced by any known .kpm (the freshly built demos in
kpms/*/ plus previous-generation .kpm files passed as extra paths) could not
resolve on either backend:

  compat-table   present in the kpimg .kp.symbol exports or the LKM table
  module-export  GLOBAL symbol of another KPM (KPM_EXPORT cross-KPM import)
  slot+kernel    kf_/kv_ pointer ABI (or printk/kallsyms_* slots), backfilled
                 from kallsyms by kpm_symbol_resolve at load time
  KERNEL-ONLY    only resolvable if the running kernel has the symbol --
                 unverifiable off-device, fatal for previous-generation KPMs

The kpimg export set is read from kernel/kpimg.elf (build it first).
"""
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NM = 'aarch64-linux-gnu-nm'
OLD_DEMOS = Path('/workspace/KernelPatch-review/artifacts')


def kpimg_exports():
    elf = ROOT / 'kernel' / 'kpimg.elf'
    if not elf.exists():
        sys.exit('kernel/kpimg.elf missing; build it first')
    out = subprocess.run([NM, str(elf)], capture_output=True, text=True).stdout
    names = set()
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[2].startswith('__kp_symbol_'):
            names.add(parts[2][len('__kp_symbol_'):])
    return names


def lkm_exports():
    src = (ROOT / 'lkm' / 'kpm' / 'symbols.c').read_text()
    lits = re.findall(r'\{\s*"([^"]+)"\s*,', src)
    kfuncs = ['kf_' + m for m in re.findall(r'KP_KPM_KFUNC_ENTRY\((\w+)\)', src)]
    names = set(lits) | set(kfuncs)
    names.discard('kf_name')  # macro parameter artifact, not a real symbol
    return names


def elf_syms(path, want):
    out = subprocess.run(['readelf', '-sW', str(path)], capture_output=True, text=True).stdout
    syms = set()
    for line in out.splitlines():
        c = line.split()
        if len(c) < 8 or not c[0].rstrip(':').isdigit():
            continue
        bind, ndx, name = c[4], c[6], c[7]
        if want == 'und' and ndx == 'UND' and name not in ('', 'UND'):
            syms.add(name)
        elif want == 'global' and bind == 'GLOBAL' and ndx != 'UND':
            syms.add(name)
    return syms


def classify(sym, table):
    if sym in table:
        return 'compat-table'
    if sym.startswith(('kf_', 'kv_')):
        return 'slot+kernel'
    if sym in ('printk', 'kallsyms_lookup_name', 'kallsyms_on_each_symbol'):
        return 'slot+kernel'
    return 'KERNEL-ONLY'


def main():
    kpimg, lkm = kpimg_exports(), lkm_exports()

    kpms = {}
    for p in sorted((ROOT / 'kpms').glob('*/*.kpm')):
        kpms[p] = 'current'
    for arg in sys.argv[1:] or ([OLD_DEMOS] if OLD_DEMOS.exists() else []):
        base = Path(arg)
        for p in sorted(base.glob('*.kpm')):
            kpms.setdefault(p, 'previous-generation')

    providers = set()
    for p in kpms:
        providers |= elf_syms(p, 'global')

    rows, failures = {}, []
    for p, gen in kpms.items():
        for sym in sorted(elf_syms(p, 'und')):
            k, l = classify(sym, kpimg), classify(sym, lkm)
            if 'KERNEL-ONLY' in (k, l) and sym in providers and k == 'KERNEL-ONLY' and l == 'KERNEL-ONLY':
                k = l = 'module-export'  # cross-KPM import of another KPM's GLOBAL
            rows.setdefault(sym, {})[p.name] = (gen, k, l)
            if 'KERNEL-ONLY' in (k, l):
                failures.append((sym, gen, p.name, k, l))

    print(f"kpimg exports: {len(kpimg)}   LKM table: {len(lkm)}   KPMs checked: {len(kpms)}\n")
    print(f"{'symbol':36} {'kpimg':14} {'lkm':14} {'gen':20} used by")
    for sym in sorted(rows):
        for mod, (gen, k, l) in sorted(rows[sym].items()):
            print(f"{sym:36} {k:14} {l:14} {gen:20} {mod}")

    if failures:
        print('\nFAIL: symbols unresolvable without a matching kernel symbol:')
        for sym, gen, mod, k, l in failures:
            print(f"  {sym} ({gen}, {mod}): kpimg={k} lkm={l}")
        return 1
    print('\nPASS: every referenced symbol resolves on both backends')
    return 0


if __name__ == '__main__':
    sys.exit(main())
