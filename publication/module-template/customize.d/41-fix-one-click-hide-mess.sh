#!/system/bin/sh

# Restore the configuration paths used by HMA. UID snapshots are managed by
# UidPolicyPublisher and can contain many retained generations.

if [ -d /data/misc/hide_my_applist ]
then
    ui_print "- Non-randomized config folder detected, fixing it"
    mv /data/misc/hide_my_applist /data/misc/hide_my_applist_$(tr -dc 'a-z0-9' < /dev/urandom | dd bs=1 count=16 2>/dev/null)
fi

hma_config_perm() {
    chown system:system "$2" || abort "! Failed to restore HMA owner: $2"
    chmod "$1" "$2" || abort "! Failed to restore HMA permissions: $2"
}

for hma_config_dir in /data/misc/hide_my_applist*; do
    [ -d "$hma_config_dir" ] || continue
    ui_print "- Repairing HMA config permissions: ${hma_config_dir##*/}"
    hma_config_perm 700 "$hma_config_dir"
    for hma_config_name in config.json preset_cache.json preset_cache_v2.json \
        filter_count filter_count.json status.json maps_module_thread.txt; do
        hma_config_file="$hma_config_dir/$hma_config_name"
        [ -f "$hma_config_file" ] || continue
        hma_config_perm 600 "$hma_config_file"
    done
    if [ -d "$hma_config_dir/log" ]; then
        hma_config_perm 700 "$hma_config_dir/log"
        for hma_config_name in runtime.log old.log; do
            hma_config_file="$hma_config_dir/log/$hma_config_name"
            [ -f "$hma_config_file" ] || continue
            hma_config_perm 600 "$hma_config_file"
        done
    fi
done

unset hma_config_dir hma_config_name hma_config_file
unset -f hma_config_perm
ui_print "- HMA configuration permissions ready"
