#!/system/bin/sh
set -eu
[ "$(id -u)" = 0 ] || { echo '需要 Root'; exit 1; }
BACKUP=${1:?请指定安装时输出的备份目录}
MODULE=/data/adb/modules/hma_oss_zygisk
[ -d "$MODULE/zygisk" ] || { echo '未找到 HMA 后端'; exit 1; }
SAVE=/data/adb/hma_uid_backups/before-restore-$(date +%Y%m%d-%H%M%S)-$$
mkdir -p "$SAVE/zygisk"
chmod 0700 "$SAVE"
for NAME in classes.dex zygisk/arm64-v8a.so module.prop; do
    [ -s "$BACKUP/$NAME" ] || { echo "备份文件缺失：$NAME"; exit 1; }
    cp -p "$MODULE/$NAME" "$SAVE/$NAME"
    cp "$BACKUP/$NAME" "$MODULE/$NAME.uid-restore"
    chmod 0644 "$MODULE/$NAME.uid-restore"
    chown 0:0 "$MODULE/$NAME.uid-restore"
    chcon u:object_r:system_file:s0 "$MODULE/$NAME.uid-restore" 2>/dev/null || true
done
for NAME in classes.dex zygisk/arm64-v8a.so module.prop; do
    mv -f "$MODULE/$NAME.uid-restore" "$MODULE/$NAME"
done
echo '后端已恢复；请恢复配套管理器 APK，再重启手机。配置备份保留原位。'
echo "本次替换前的后端保存在：$SAVE"
