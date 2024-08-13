#!/bin/sh

KPMS_DIR="/data/adb/ap/kpms/"
MAGISK_POLICY_PATH="/data/adb/ap/bin/magiskpolicy"
SUPERCMD="truncate"
MAGISK_SCTX="u:r:magisk:s0"
APD_PATH="/data/adb/apd"

skey="$1"
event="$2"

LOG_FILE="/dev/user_init_""$event"".log"

exec >>$LOG_FILE 2>&1

set -x

load_modules() {
    for dir in "$KPMS_DIR/*"; do
        if [ ! -d "$dir" ]; then continue; fi
        if [ -e "$dir/disable" ]; then continue; fi
        main_sh="$dir/main.sh"
        if [ -e "$main_sh" ]; then
            touch "$dir/disable"
            echo "loading $dir/main.sh ..."
            . "$main_sh"
            rm -f "$dir/disable"
        else
            echo "Error: $main_sh not found in $dir"
        fi
    done
}

handle() {
    $SUPERCMD $skey event $event "before"
    case "$event" in
    "early-init" | "init" | "late-init") ;;
    "post-fs-data")
        $MAGISK_POLICY_PATH --magisk --live
        load_modules $skey $event
        $SUPERCMD $skey -Z $MAGISK_SCTX exec $APD_PATH -s $skey $event
        ;;
    "services")
        $SUPERCMD $skey -Z $MAGISK_SCTX exec $APD_PATH -s $skey $event
        ;;
    "boot-completed")
        $SUPERCMD $skey -Z $MAGISK_SCTX exec $APD_PATH -s $skey $event
        $SUPERCMD su -Z $MAGISK_SCTX exec $APD_PATH uid-listener &
        ;;
    *)
        echo "unknown user_init event: $event"
        ;;
    esac
    $SUPERCMD $skey event $event "after"
}

handle
