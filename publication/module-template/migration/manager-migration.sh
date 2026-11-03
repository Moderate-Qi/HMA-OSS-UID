#!/system/bin/sh
# HMA-specific signature migration. Backups remain outside the module directory.
# The user-authorized uninstall is limited to this exact manager package.

HMA_MM_PKG=org.frknkrc44.hma_oss
HMA_MM_BACKUP=
HMA_MM_REMOVED=0

hma_mm_command() {
    # Android shell commands pass stdout/stderr descriptors to system_server.
    # A pipe keeps root-private backup/log files out of that Binder transaction.
    local output status
    output="$("$@" 2>&1)"
    status=$?
    printf '%s\n' "$output"
    return "$status"
}

hma_mm_helper() {
    CLASSPATH="$MODPATH/migration/helper.dex" app_process /system/bin HmaManagerMigration "$@"
}

hma_mm_install_apk() {
    local user="$1" apk="$2" replace="$3" size
    size="$(stat -c %s "$apk")" || return 1
    if [ "$replace" = 1 ]; then
        cat "$apk" | hma_mm_command pm install -r --user "$user" -S "$size"
    else
        cat "$apk" | hma_mm_command pm install --user "$user" -S "$size"
    fi
}

hma_mm_install_saved() {
    local output session apk size
    set -- "$HMA_MM_BACKUP"/apk/*.apk
    if [ "$#" -eq 1 ]; then
        hma_mm_install_apk "$HMA_MM_FIRST" "$1" 0
        return $?
    fi
    output="$(hma_mm_command pm install-create --user "$HMA_MM_FIRST")" || return 1
    printf '%s\n' "$output"
    session="$(printf '%s\n' "$output" | sed -n 's/.*\[\([0-9][0-9]*\)\].*/\1/p')"
    [ -n "$session" ] || return 1
    for apk in "$@"; do
        size="$(stat -c %s "$apk")" || return 1
        cat "$apk" | hma_mm_command pm install-write -S "$size" "$session" "${apk##*/}" - || return 1
    done
    hma_mm_command pm install-commit "$session"
}

hma_mm_installed() {
    pm list packages --user "$1" "$HMA_MM_PKG" 2>/dev/null | grep -Fx "package:$HMA_MM_PKG" >/dev/null
}

hma_mm_users() {
    local candidate
    for candidate in $(pm list users | sed -n 's/.*UserInfo{\([0-9][0-9]*\):.*/\1/p'); do
        hma_mm_installed "$candidate" && echo "$candidate"
    done
    return 0
}

hma_mm_compare_tree() {
    local origin="$1" target="$2" listing="$3" relative
    (cd "$origin" && find . \( -path ./cache -o -path ./code_cache -o -path ./lib \) -prune -o -type f -print) > "$listing" || return 1
    while IFS= read -r relative; do
        cmp -s "$origin/$relative" "$target/$relative" || return 1
    done < "$listing"
}

hma_mm_backup_data() {
    local user="$1" kind="$2" base="$3" archive check
    [ -d "$base/$user/$HMA_MM_PKG" ] || return 0
    archive="$HMA_MM_BACKUP/$kind-$user.tar"
    check="$HMA_MM_BACKUP/check-$kind-$user"
    mkdir -p "$check" || return 1
    tar -cpf "$archive" --exclude=./cache --exclude=./code_cache --exclude=./lib \
        -C "$base/$user/$HMA_MM_PKG" . || return 1
    tar -xpf "$archive" -C "$check" || return 1
    hma_mm_compare_tree "$base/$user/$HMA_MM_PKG" "$check" "$HMA_MM_BACKUP/files-$kind-$user.txt" || return 1
}

hma_mm_backup() {
    local user path index=0 directory filename source saved
    umask 077
    mkdir -p /data/adb/hma_oss_manager_backup || return 1
    HMA_MM_BACKUP="/data/adb/hma_oss_manager_backup/$(date +%Y%m%d-%H%M%S)-$$"
    mkdir "$HMA_MM_BACKUP" || return 1
    chmod 0700 /data/adb/hma_oss_manager_backup "$HMA_MM_BACKUP" || return 1
    printf '%s\n' "$HMA_MM_USERS" > "$HMA_MM_BACKUP/users.txt" || return 1
    mkdir "$HMA_MM_BACKUP/apk" "$HMA_MM_BACKUP/service" || return 1
    mkdir -p "$HMA_MM_BACKUP/recovery/migration" || return 1
    for filename in helper.dex manager-migration.sh; do
        cp -p "$MODPATH/migration/$filename" "$HMA_MM_BACKUP/recovery/migration/$filename" || return 1
        cmp -s "$MODPATH/migration/$filename" "$HMA_MM_BACKUP/recovery/migration/$filename" || return 1
    done
    cp -p "$MODPATH/migration/restore-previous.sh" "$HMA_MM_BACKUP/restore-previous.sh" || return 1
    cmp -s "$MODPATH/migration/restore-previous.sh" "$HMA_MM_BACKUP/restore-previous.sh" || return 1
    chmod 0700 "$HMA_MM_BACKUP/restore-previous.sh" || return 1
    hma_mm_command pm path --user "$HMA_MM_FIRST" "$HMA_MM_PKG" > "$HMA_MM_BACKUP/apk-paths.txt" || return 1
    while IFS= read -r path; do
        case "$path" in package:*) path="${path#package:}" ;; *) return 1 ;; esac
        saved="$HMA_MM_BACKUP/apk/$index.apk"
        cp -p "$path" "$saved" && cmp -s "$path" "$saved" || return 1
        index=$((index + 1))
    done < "$HMA_MM_BACKUP/apk-paths.txt"
    [ "$index" -gt 0 ] || return 1
    for user in $HMA_MM_USERS; do
        hma_mm_command am force-stop --user "$user" "$HMA_MM_PKG" || return 1
        hma_mm_helper capture "$user" "$HMA_MM_BACKUP/state-$user.properties" || return 1
        hma_mm_backup_data "$user" ce /data/user || return 1
        hma_mm_backup_data "$user" de /data/user_de || return 1
    done
    : > "$HMA_MM_BACKUP/service-paths.txt" || return 1
    index=0
    for directory in /data/misc/hide_my_applist_* /data/system/hide_my_applist_*; do
        [ -d "$directory" ] || continue
        for filename in config.json preset_cache.json preset_cache_v2.json filter_count.json; do
            source="$directory/$filename"
            [ -f "$source" ] || continue
            saved="$HMA_MM_BACKUP/service/$index"
            cp -p "$source" "$saved" && cmp -s "$source" "$saved" || return 1
            printf '%s\t%s\n' "$index" "$source" >> "$HMA_MM_BACKUP/service-paths.txt" || return 1
            index=$((index + 1))
        done
    done
    echo verified > "$HMA_MM_BACKUP/backup-verified" || return 1
    echo BACKUP_VERIFIED > "$HMA_MM_BACKUP/status.txt" || return 1
    ui_print "- HMA manager backup verified: $HMA_MM_BACKUP"
}

hma_mm_restore_data() {
    local user="$1" kind="$2" base="$3" uid="$4" archive target
    archive="$HMA_MM_BACKUP/$kind-$user.tar"
    [ -f "$archive" ] || return 0
    target="$base/$user/$HMA_MM_PKG"
    [ -d "$target" ] || return 1
    tar -xpf "$archive" -C "$target" || return 1
    chown -R "$uid:$uid" "$target" || return 1
    restorecon -RF "$target" || return 1
    hma_mm_compare_tree "$HMA_MM_BACKUP/check-$kind-$user" "$target" \
        "$HMA_MM_BACKUP/restored-files-$kind-$user.txt" || return 1
}

hma_mm_restore() {
    local expected="$1" user uid index target
    for user in $HMA_MM_USERS; do
        hma_mm_installed "$user" || hma_mm_command pm install-existing --user "$user" "$HMA_MM_PKG" || return 1
        hma_mm_command am force-stop --user "$user" "$HMA_MM_PKG" || return 1
        uid="$(hma_mm_helper uid "$user")" || return 1
        case "$uid" in ''|*[!0-9]*) return 1 ;; esac
        hma_mm_restore_data "$user" ce /data/user "$uid" || return 1
        hma_mm_restore_data "$user" de /data/user_de "$uid" || return 1
        hma_mm_helper restore "$user" "$HMA_MM_BACKUP/state-$user.properties" || return 1
        hma_mm_helper verify "$user" "$HMA_MM_BACKUP/state-$user.properties" "$expected" || return 1
    done
    while IFS="$(printf '\t')" read -r index target; do
        [ -n "$index" ] || continue
        cp -p "$HMA_MM_BACKUP/service/$index" "$target" || return 1
        restorecon "$target" || return 1
        cmp -s "$HMA_MM_BACKUP/service/$index" "$target" || return 1
    done < "$HMA_MM_BACKUP/service-paths.txt"
}

hma_mm_rollback() {
    local result MODPATH="$HMA_MM_BACKUP/recovery"
    ui_print "- Restoring the previous HMA manager and configuration"
    if test -n "$(pm list packages --user -1 "$HMA_MM_PKG" 2>/dev/null)"; then
        hma_mm_command pm uninstall "$HMA_MM_PKG" >> "$HMA_MM_BACKUP/rollback.log" 2>&1 || return 1
    fi
    hma_mm_install_saved >> "$HMA_MM_BACKUP/rollback.log" 2>&1 || return 1
    hma_mm_restore original >> "$HMA_MM_BACKUP/rollback.log" 2>&1 || return 1
    HMA_MM_REMOVED=0
    echo ROLLED_BACK > "$HMA_MM_BACKUP/status.txt"
    ui_print "- Previous HMA manager and configuration restored"
}

hma_mm_fail() {
    local phase="$1"
    if [ "$HMA_MM_REMOVED" = 1 ]; then
        if ! hma_mm_rollback; then
            echo RECOVERY_REQUIRED > "$HMA_MM_BACKUP/status.txt"
            ui_print "! Restore the saved APK/data from: $HMA_MM_BACKUP"
        fi
        HMA_MM_REMOVED=0
    fi
    abort "! HMA manager migration stopped at $phase. Backup: $HMA_MM_BACKUP"
}

hma_mm_on_exit() {
    local code="$1"
    trap - EXIT
    if [ "$HMA_MM_REMOVED" = 1 ]; then
        if ! hma_mm_rollback; then
            echo RECOVERY_REQUIRED > "$HMA_MM_BACKUP/status.txt"
            ui_print "! Recovery backup: $HMA_MM_BACKUP"
        fi
        [ "$code" -ne 0 ] || code=1
    fi
    exit "$code"
}

hma_install_manager() {
    local apk="$1" output user
    HMA_MM_USERS="$(hma_mm_users)"
    HMA_MM_FIRST="$(printf '%s\n' "$HMA_MM_USERS" | head -n 1)"
    if [ -z "$HMA_MM_FIRST" ]; then
        ui_print "- Installing HMA manager for user 0"
        hma_mm_install_apk 0 "$apk" 1 || abort "! HMA manager installation failed"
        return 0
    fi
    ui_print "- Updating HMA manager for user $HMA_MM_FIRST"
    output="$(hma_mm_install_apk "$HMA_MM_FIRST" "$apk" 1)" && {
        printf '%s\n' "$output"
        return 0
    }
    printf '%s\n' "$output"
    printf '%s\n' "$output" | grep -F 'INSTALL_FAILED_UPDATE_INCOMPATIBLE' >/dev/null || \
        abort "! HMA manager update failed; existing app and configuration retained"
    ui_print "- Signature migration: backing up HMA manager and configuration"
    hma_mm_backup >> "$MODPATH/manager-migration.log" 2>&1 || hma_mm_fail backup
    ui_print "- Backup verified: $HMA_MM_BACKUP"
    printf '%s\n' "$output" > "$HMA_MM_BACKUP/original-install-error.txt"
    hma_mm_command pm uninstall "$HMA_MM_PKG" >> "$HMA_MM_BACKUP/migration.log" 2>&1 || hma_mm_fail uninstall
    HMA_MM_REMOVED=1
    echo OLD_MANAGER_REMOVED > "$HMA_MM_BACKUP/status.txt"
    hma_mm_install_apk "$HMA_MM_FIRST" "$apk" 0 >> "$HMA_MM_BACKUP/migration.log" 2>&1 || hma_mm_fail install
    hma_mm_restore "$MODPATH/migration/manager-cert.der" >> "$HMA_MM_BACKUP/migration.log" 2>&1 || hma_mm_fail restore
    HMA_MM_REMOVED=0
    echo MIGRATED_AND_VERIFIED > "$HMA_MM_BACKUP/status.txt"
    ui_print "- HMA manager configuration restored and verified for all installed users"
    ui_print "- Recovery backup retained: $HMA_MM_BACKUP"
}
