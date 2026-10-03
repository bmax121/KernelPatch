#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Cross-version KPM symbol compatibility gate.

Usage: symbol_compat.py [extra.kpm dirs...]

Fails when a symbol referenced by any known .kpm (the freshly built demos in
kpms/*/ plus previous-generation .kpm files passed as extra paths) could not
resolve on either backend.

The kpimg export set is read from kernel/kpimg.elf (build it first).  Provider
names come from each KPM's own .kpm.export section, which is what the loader
actually consults -- not from its global symbol table, so an ordinary global
helper cannot make an unresolved import pass.

Exit status:
  0  every referenced symbol resolves on both backends
  1  at least one symbol is unresolvable
  2  the gate could not run (no kpimg.elf, or no .kpm inputs found)
"""
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NM = 'aarch64-linux-gnu-nm'
SECTION = '.kpm.export'


def require_tool(name):
    if shutil.which(name) is None:
        sys.exit(f'required tool not found in PATH: {name}')


def kpimg_exports():
    """Names the kpimg runtime publishes to KPMs (kernel/kpimg.elf)."""
    require_tool(NM)
    require_tool('readelf')
    elf = ROOT / 'kernel' / 'kpimg.elf'
    if not elf.exists():
        sys.exit('kernel/kpimg.elf missing; build it first')
    out = subprocess.run([NM, str(elf)], capture_output=True, text=True).stdout
    names = set()
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[2].startswith('__kp_symbol_'):
            names.add(parts[2][len('__kp_symbol_'):])
    if not names:
        sys.exit('no __kp_symbol_* entries in kernel/kpimg.elf; is it built?')
    return names


def lkm_exports():
    """Names the LKM backend publishes (lkm/kpm/symbols.c)."""
    src = ROOT / 'lkm' / 'kpm' / 'symbols.c'
    if not src.exists():
        sys.exit('lkm/kpm/symbols.c missing')
    text = src.read_text()
    lits = re.findall(r'\{\s*"([^"]+)"\s*,', text)
    kfuncs = ['kf_' + m for m in re.findall(r'KP_KPM_KFUNC_ENTRY\((\w+)\)', text)]
    names = set(lits) | set(kfuncs)
    names.discard('kf_name')  # macro parameter artifact, not a real symbol
    return names


def export_names(kpm):
    """Return only identifiers emitted by KPM_EXPORT in this object file.

    KPM_EXPORT(foo) creates a local section object named
    __kpm_export_foo. Ordinary GLOBAL functions are not exports, and a
    function explicitly exported by the macro may itself be static.
    """
    out = subprocess.run(['readelf', '-sW', str(kpm)], capture_output=True, text=True)
    if out.returncode:
        raise RuntimeError(f'readelf failed for {kpm}: {out.stderr.strip()}')
    prefix = '__kpm_export_'
    return {
        fields[7][len(prefix):]
        for line in out.stdout.splitlines()
        if len(fields := line.split()) >= 8
        and fields[0].rstrip(':').isdigit()
        and fields[6] != 'UND'
        and fields[7].startswith(prefix)
    }


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


def collect_kpms():
    kpms = {}
    for p in sorted((ROOT / 'kpms').glob('*/*.kpm')):
        kpms[p] = 'current'
    for arg in sys.argv[1:]:
        path = Path(arg)
        candidates = sorted(path.glob('*.kpm')) if path.is_dir() else [path]
        for p in candidates:
            if p.is_file():
                kpms.setdefault(p, 'previous-generation')
    return kpms


def main():
    kpimg, lkm = kpimg_exports(), lkm_exports()

    kpms = collect_kpms()
    if not kpms:
        # A clean checkout has kpimg.elf but no built .kpm files.  Reporting
        # PASS here would make the gate succeed without checking anything.
        print('FAIL: no .kpm inputs found (build the demos, or pass a '
              'directory containing .kpm files)', file=sys.stderr)
        return 2

    providers = set()
    for p in kpms:
        providers |= export_names(p)

    rows, failures = {}, []
    for p, gen in kpms.items():
        for sym in sorted(elf_syms(p, 'und')):
            k, l = classify(sym, kpimg), classify(sym, lkm)
            if k == 'KERNEL-ONLY' and l == 'KERNEL-ONLY' and sym in providers:
                k = l = 'module-export'  # provided by another KPM
            rows.setdefault(sym, {})[p.name] = (gen, k, l)
            if 'KERNEL-ONLY' in (k, l):
                failures.append((sym, gen, p.name, k, l))

    print(f"kpimg exports: {len(kpimg)}   LKM table: {len(lkm)}   "
          f"KPMs checked: {len(kpms)}   KPM providers: {len(providers)}\n")
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