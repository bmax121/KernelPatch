#!/bin/sh
set -eux

GKI_ROOT=$(pwd)

echo "[+] GKI_ROOT: $GKI_ROOT"

if test -d "$GKI_ROOT/common/drivers"; then
     DRIVER_DIR="$GKI_ROOT/common/drivers"
elif test -d "$GKI_ROOT/drivers"; then
     DRIVER_DIR="$GKI_ROOT/drivers"
else
     echo '[ERROR] "drivers/" directory is not found.'
     echo '[+] You should modify this script by yourself.'
     exit 127
fi

test -d "$GKI_ROOT/KernelPatch" || git clone https://github.com/bmax121/KernelPatch
cd "$GKI_ROOT/KernelPatch"
git stash
if [ "$(git status | grep -Po 'v\d+(\.\d+)*' | head -n1)" ]; then
     git checkout main
fi
git pull
if [ -z "${1-}" ]; then
    git checkout "$(git describe --abbrev=0 --tags)"
else
    git checkout "$1"
fi
cd "$GKI_ROOT"

echo "[+] GKI_ROOT: $GKI_ROOT"
echo "[+] Copy KernelPatch driver to $DRIVER_DIR"

cd "$DRIVER_DIR"
if test -d "$GKI_ROOT/common/drivers"; then
     ln -sf "../../KernelPatch/kernel" "kPatch"
elif test -d "$GKI_ROOT/drivers"; then
     ln -sf "../KernelPatch/kernel" "kPatch"
fi
find ./kernel/ -type f -name "*.c" -exec sed -i 's|<\([^=<>-]\{1,10\}\)>|"\1"|g' {} \;
find ./kernel/ -type f -name "*.h" -exec sed -i 's|<\([^=<>-]\{1,10\}\)>|"\1"|g' {} \;
cd "$GKI_ROOT"

echo '[+] Add KernelPatch driver to Makefile'

DRIVER_MAKEFILE=$DRIVER_DIR/Makefile
DRIVER_KCONFIG=$DRIVER_DIR/Kconfig
grep -q "kPatch" "$DRIVER_MAKEFILE" || printf "obj-\$(CONFIG_Apatch) += kPatch/\n" >> "$DRIVER_MAKEFILE"
grep -q "kPatch" "$DRIVER_KCONFIG" || sed -i "/endmenu/i\\source \"drivers/kPatch/Kconfig\"" "$DRIVER_KCONFIG"

echo '[+] Done.'
