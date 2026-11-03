"""Build the ARM64-only loader with the scoped UID extension. No cleanup steps."""
from pathlib import Path
import os
import subprocess
import zipfile

root = Path(__file__).resolve().parent
def locate_toolchain():
    explicit = os.environ.get('NDK_TOOLCHAIN')
    if explicit:
        return Path(explicit)
    home = os.environ.get('ANDROID_NDK_HOME') or os.environ.get('ANDROID_NDK_ROOT')
    if not home:
        raise SystemExit('Set ANDROID_NDK_HOME or NDK_TOOLCHAIN to Android NDK r27c')
    host = 'windows-x86_64' if os.name == 'nt' else ('darwin-x86_64' if __import__('sys').platform == 'darwin' else 'linux-x86_64')
    return Path(home) / 'toolchains/llvm/prebuilt' / host

toolchain = locate_toolchain()
clang = toolchain / ('bin/clang++.exe' if os.name == 'nt' else 'bin/clang++')
src = root / 'uid-native/runtime'
out = root / 'uid-native/build'
out.mkdir(parents=True, exist_ok=True)
target = out / 'arm64-v8a.so'
cmd = [str(clang), '--target=aarch64-linux-android29', '--sysroot=' + str(toolchain / 'sysroot'),
       '-shared', '-fPIC', '-std=c++17', '-O2', '-fvisibility=hidden', '-fvisibility-inlines-hidden',
       '-fno-rtti', '-fdata-sections', '-ffunction-sections', '-static-libstdc++',
       '-Wl,--gc-sections', '-Wl,--exclude-libs,ALL', '-Wl,-Bsymbolic',
       '-Wl,-z,max-page-size=16384', '-Wl,--version-script=' + str(root / 'uid-native/exports.map'),
       '-Wl,--no-undefined', '-o', str(target),
       *[str(src / name) for name in ['main.cpp', 'dex.cpp', 'atexit.cpp', 'uid_filter.cpp', 'uid_broker.cpp']], '-llog', '-ldl']
subprocess.run(cmd, check=True)
print(f'Built {target}: {target.stat().st_size} bytes')
