"""Embed the separately built service dex and matching native loader into the manager."""
from pathlib import Path
import zipfile

root = Path(__file__).resolve().parent
apks = list((root / 'zygote/build/outputs/apk/release').glob('*.apk'))
if len(apks) != 1:
    raise SystemExit(f'Expected one backend APK, got {apks}')
target = root / 'app/src/main/assets/uid-backend.zip'
with zipfile.ZipFile(apks[0]) as apk, zipfile.ZipFile(target, 'w', zipfile.ZIP_DEFLATED) as out:
    dex = [n for n in apk.namelist() if n.startswith('classes') and n.endswith('.dex')]
    if dex != ['classes.dex']:
        raise SystemExit(f'Unexpected backend dex layout: {dex}')
    out.writestr('payload/classes.dex', apk.read('classes.dex'))
    out.write(root / 'uid-native/build/arm64-v8a.so', 'payload/zygisk/arm64-v8a.so')
    out.write(root / 'uid-native/install-backend.sh', 'install-backend.sh')
    out.write(root / 'uid-native/restore-backend.sh', 'restore-backend.sh')
    out.writestr('payload/module.prop', '''id=hma_oss_zygisk
name=HMA-OSS Zygisk + UID
version=1eda3ef1-UID3.1
versionCode=7304663
minSdkVersion=29
author=frknkrc44; local scoped UID integration
description=System service loaded by HMA; optional scoped ARM64 UID filtering
entrypoint=org.frknkrc44.hma_oss.zygote.ZygoteEntry
attachNativeLibs=false
''')
print(f'Embedded backend payload: {target.stat().st_size} bytes')
