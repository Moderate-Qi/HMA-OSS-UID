"""Run the delivered installers against isolated host fixtures; no phone access."""
from pathlib import Path
import subprocess
import time

source = Path(__file__).resolve().parents[2]
base = source.parent / 'evidence' / ('installer-fixture-' + str(time.time_ns()))
base.mkdir(parents=True)
module = base / 'module'
(module / 'zygisk').mkdir(parents=True)
payload = base / 'payload-root'
(payload / 'payload/zygisk').mkdir(parents=True)
old = {'module.prop': b'id=hma_oss_zygisk\nversion=original\n', 'classes.dex': b'original-dex', 'zygisk/arm64-v8a.so': b'original-loader'}
new = {'module.prop': b'id=hma_oss_zygisk\nversion=test\n', 'classes.dex': b'new-dex', 'zygisk/arm64-v8a.so': b'new-loader'}
for name in old:
    (module / name).write_bytes(old[name])
    (payload / 'payload' / name).write_bytes(new[name])
for name in ['install-backend.sh', 'restore-backend.sh']:
    text = (source / 'uid-native' / name).read_text(encoding='utf-8')
    text = text.replace('/data/adb/modules/hma_oss_zygisk', str(module))
    text = text.replace('/data/adb/modules_update/hma_oss_zygisk', str(base / 'pending'))
    text = text.replace('/data/adb/hma_uid_backups', str(base / 'backups'))
    text = text.replace('/data/misc/hide_my_applist_*', str(base / 'configs/hide_my_applist_*'))
    (payload / name).write_text(text, encoding='utf-8')
    subprocess.run(['sh', '-n', str(payload / name)], check=True)
result = subprocess.run(['sh', str(payload / 'install-backend.sh'), str(payload)], text=True, capture_output=True, check=True)
backup = next((base / 'backups').iterdir())
assert all((module / name).read_bytes() == value for name, value in new.items())
assert all((backup / name).read_bytes() == value for name, value in old.items())
restore = subprocess.run(['sh', str(payload / 'restore-backend.sh'), str(backup)], text=True, capture_output=True, check=True)
assert all((module / name).read_bytes() == value for name, value in old.items())
# A pending systemless update must leave the current files unchanged.
(base / 'pending').mkdir()
pending = subprocess.run(['sh', str(payload / 'install-backend.sh'), str(payload)], text=True, capture_output=True)
assert pending.returncode != 0
assert all((module / name).read_bytes() == value for name, value in old.items())
print('PASS installer: backup / atomic file replacement / restore / pending-update refusal')
print('Fixture retained:', base)
