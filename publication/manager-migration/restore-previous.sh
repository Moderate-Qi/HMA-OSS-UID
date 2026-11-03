#!/system/bin/sh
# Run as root to restore this backup's previous manager and configuration.
HMA_MM_SAVED_DIR="${0%/*}"
[ -f "$HMA_MM_SAVED_DIR/backup-verified" ] || {
    echo 'This backup did not complete verification; the installed manager is retained' >&2
    exit 1
}
MODPATH="$HMA_MM_SAVED_DIR/recovery"
ui_print() { echo "$*"; }
. "$MODPATH/migration/manager-migration.sh"
HMA_MM_BACKUP="$HMA_MM_SAVED_DIR"
HMA_MM_USERS="$(cat "$HMA_MM_BACKUP/users.txt")"
HMA_MM_FIRST="$(printf '%s\n' "$HMA_MM_USERS" | head -n 1)"
[ -n "$HMA_MM_FIRST" ] || { echo 'Saved manager user list is empty' >&2; exit 1; }
hma_mm_rollback || {
    echo RECOVERY_REQUIRED > "$HMA_MM_BACKUP/status.txt"
    echo "Recovery data retained: $HMA_MM_BACKUP" >&2
    exit 1
}
