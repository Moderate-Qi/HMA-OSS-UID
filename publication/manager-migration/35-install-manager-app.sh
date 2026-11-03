#!/system/bin/sh
if (
    . "$MODPATH/migration/manager-migration.sh"
    trap 'hma_mm_on_exit $?' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM HUP
    hma_install_manager "$MODPATH/manager.apk"
); then
    ui_print "- HMA manager installation complete"
else
    abort "! HMA manager installation stopped; see migration log and retained backup"
fi
