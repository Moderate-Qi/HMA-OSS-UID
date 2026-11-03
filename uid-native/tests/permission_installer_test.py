"""Run the actual permission step with retained fixtures and recorded ownership calls.

Small and large UID histories must produce the same configuration operations.
No Android paths are accessed. No fixture files are removed.
"""
from pathlib import Path
import os
import shutil
import subprocess
import time

source = Path(__file__).resolve().parents[2]
fixture = source.parent / 'evidence' / ('permission-installer-' + str(time.time_ns()))
fixture.mkdir(parents=True)
script = (source / 'publication/module-template/customize.d/41-fix-one-click-hide-mess.sh').read_text(encoding='utf-8')
assert script == (source / 'zygote/src/main/assets/customize.d/41-fix-one-click-hide-mess.sh').read_text(encoding='utf-8')
shell = 'C:/Program Files/Git/bin/bash.exe' if os.name == 'nt' else shutil.which('bash')
subprocess.run([shell, '-n'], input=script.encode('utf-8'), check=True)

def scenario(name, history_files, fail=False, empty=False):
    case = fixture / name
    misc = case / 'misc'
    misc.mkdir(parents=True)
    config = misc / 'hide_my_applist_test'
    data = b'{"uidFilterEnabled":true,"scope":{"target":{}}}\n'
    if not empty:
        config.mkdir()
        for filename in ['config.json', 'preset_cache.json', 'preset_cache_v2.json',
                         'filter_count', 'filter_count.json', 'status.json', 'maps_module_thread.txt']:
            (config / filename).write_bytes(data)
        (config / 'log').mkdir()
        for filename in ['runtime.log', 'old.log']:
            (config / 'log' / filename).write_bytes(b'preserved log\n')
        for i in range(history_files):
            generation = config / 'uid_scope' / ('g123_' + str(i // 128))
            generation.mkdir(parents=True, exist_ok=True)
            (generation / str(10000 + i % 128)).write_bytes(b'HMA_UID_3\n10000\n10477\n')
    prefix = r'''
ui_print() { printf '%s\n' "$*"; }
abort() { printf '%s\n' "$*" >&2; exit 97; }
find() { printf 'unexpected recursive traversal\n' >&2; exit 96; }
chown() {
    [ "$1" = system:system ] && [ "$#" = 2 ] || exit 95
    printf 'chown\t%s\t%s\n' "$1" "$2" >> "$HMA_TEST_CALLS"
    if [ "$HMA_TEST_FAIL" = 1 ] && [ "${2##*/}" = config.json ]; then return 23; fi
}
chmod() { printf 'chmod\t%s\t%s\n' "$1" "$2" >> "$HMA_TEST_CALLS"; }
'''
    calls = case / 'calls.tsv'
    env = dict(os.environ, HMA_TEST_CALLS=calls.as_posix(), HMA_TEST_FAIL='1' if fail else '0')
    started = time.monotonic()
    result = subprocess.run([shell], input=(prefix + script.replace('/data/misc', misc.as_posix())).encode('utf-8'),
                            capture_output=True, env=env, timeout=15)
    result.stdout = result.stdout.decode('utf-8')
    result.stderr = result.stderr.decode('utf-8')
    elapsed = time.monotonic() - started
    (case / 'stdout.log').write_text(result.stdout, encoding='utf-8')
    (case / 'stderr.log').write_text(result.stderr, encoding='utf-8')
    rows = calls.read_text(encoding='utf-8').splitlines() if calls.exists() else []
    assert result.returncode == (97 if fail else 0), (name, result.stdout, result.stderr)
    assert all('/uid_scope' not in row for row in rows)
    if empty:
        assert not rows
    else:
        assert (config / 'config.json').read_bytes() == data
        if not fail:
            modes = [row.split('\t')[1:] for row in rows if row.startswith('chmod\t')]
            assert len(modes) == 11
            for mode, path in modes:
                assert mode == ('700' if Path(path).is_dir() else '600')
            assert len(list((config / 'uid_scope').rglob('*'))) == history_files + (history_files + 127) // 128
    if fail:
        assert 'Failed to restore HMA owner' in result.stderr
        assert 'permissions ready' not in result.stdout
    else:
        assert 'HMA configuration permissions ready' in result.stdout
    print(f'PASS {name}: {history_files} UID files, {len(rows)} permission calls, {elapsed:.3f}s host shell')
    return len(rows)

assert scenario('small-history', 32) == scenario('large-history', 4096) == 22
scenario('fresh-install', 0, empty=True)
scenario('permission-error', 0, fail=True)
print('Fixture retained:', fixture)
