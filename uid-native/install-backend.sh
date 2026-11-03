#!/system/bin/sh
set -eu
[ "$(id -u)" = 0 ] || { echo '需要 Root 授权'; exit 1; }
SOURCE=$1
MODULE=/data/adb/modules/hma_oss_zygisk
[ -f "$MODULE/module.prop" ] && grep -q '^id=hma_oss_zygisk$' "$MODULE/module.prop" || {
    echo '请先安装原 HMA-OSS Zygisk 模块并重启，再更新集成后端。'; exit 1;
}
[ ! -e /data/adb/modules_update/hma_oss_zygisk ] || {
    echo '已有待重启的 HMA 更新，请先完成该次更新。'; exit 1;
}
BACKUP=/data/adb/hma_uid_backups/$(date +%Y%m%d-%H%M%S)-$$
mkdir -p "$BACKUP/zygisk"
chmod 0700 /data/adb/hma_uid_backups "$BACKUP"
for OLD in "$MODULE"/classes*.dex; do
    [ -f "$OLD" ] || continue
    case "${OLD##*/}" in
        classes.dex) cp -p "$OLD" "$BACKUP/";;
        *) echo '发现多 DEX 后端，此包未验证该形式，已保留原后端。'; exit 1;;
    esac
done
cp -p "$MODULE/module.prop" "$BACKUP/module.prop"
cp -p "$MODULE/zygisk/arm64-v8a.so" "$BACKUP/zygisk/arm64-v8a.so"
cp "$SOURCE/restore-backend.sh" "$BACKUP/restore-backend.sh"
for DIR in /data/misc/hide_my_applist_*; do
    [ -f "$DIR/config.json" ] || continue
    cp -p "$DIR/config.json" "$BACKUP/${DIR##*/}-config.json"
done

# Publish new inodes rather than truncate a DSO that a live process may map.
for NAME in classes.dex zygisk/arm64-v8a.so module.prop; do
    [ -f "$SOURCE/payload/$NAME" ] || { echo '后端文件不完整'; exit 1; }
    cp "$SOURCE/payload/$NAME" "$MODULE/$NAME.uid-next"
    chmod 0644 "$MODULE/$NAME.uid-next"
    chown 0:0 "$MODULE/$NAME.uid-next"
    chcon u:object_r:system_file:s0 "$MODULE/$NAME.uid-next" 2>/dev/null || true
done
for NAME in classes.dex zygisk/arm64-v8a.so module.prop; do
    mv -f "$MODULE/$NAME.uid-next" "$MODULE/$NAME"
done
echo '集成后端已更新，原有 v3 UID 开关状态保留。'
echo '请重启手机一次；UID 过滤默认开启，已有手动开关设置继续保留。'
echo "原后端和配置已备份：$BACKUP"
echo '关闭 UID 开关后重新打开受影响应用，即可恢复，无需整机重启。'
