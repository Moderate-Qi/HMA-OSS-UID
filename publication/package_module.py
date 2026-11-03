"""Pack matching manager, backend, ARM64 loader and migration helper."""
from pathlib import Path
import argparse
import hashlib
import io
import zipfile

root=Path(__file__).resolve().parent.parent
p=argparse.ArgumentParser()
for name in ('manager','backend','native','helper','certificate','output'):
    p.add_argument('--'+name,required=True,type=Path)
a=p.parse_args()
with zipfile.ZipFile(a.backend) as z:backend=z.read('classes.dex')
with zipfile.ZipFile(a.manager) as z:
    with zipfile.ZipFile(io.BytesIO(z.read('assets/uid-backend.zip'))) as payload:
        if payload.read('payload/classes.dex')!=backend:raise SystemExit('Manager/backend DEX mismatch')
        if payload.read('payload/zygisk/arm64-v8a.so')!=a.native.read_bytes():raise SystemExit('Manager/native mismatch')
        metadata=payload.read('payload/module.prop')
template=root/'publication/module-template'
files={f.relative_to(template).as_posix():f.read_bytes() for f in template.rglob('*') if f.is_file()}
files.update({'classes.dex':backend,'manager.apk':a.manager.read_bytes(),'zygisk/arm64-v8a.so':a.native.read_bytes(),'module.prop':metadata,
              'migration/helper.dex':a.helper.read_bytes(),'migration/manager-cert.der':a.certificate.read_bytes()})
verify='''# Resource checks consumed by the installer.
ui_print "- Verify module resources"
do_verify() {
    [ -f "$MODPATH/$1" ] || abort "! Module resource '$1' not found"
    (echo "$2  $MODPATH/$1" | sha256sum -c - >/dev/null 2>&1) || abort "! Module resource '$1' verify failed"
}
'''
for name,data in sorted(files.items()):
    if name in ('customize.d/00-verify-resources.sh','customize.sh') or name.startswith('META-INF/'):continue
    verify+=f'do_verify {name} {hashlib.sha256(data).hexdigest()}\n'
files['customize.d/00-verify-resources.sh']=(verify+'unset -f do_verify\n').encode()
a.output.parent.mkdir(parents=True,exist_ok=True)
with zipfile.ZipFile(a.output,'x',zipfile.ZIP_DEFLATED) as z:
    for name,data in sorted(files.items()):
        i=zipfile.ZipInfo(name);i.create_system=3
        i.external_attr=(0o100755 if name.endswith('.sh') or name.endswith('update-binary') else 0o100644)<<16
        i.compress_type=zipfile.ZIP_DEFLATED;z.writestr(i,data)
print(a.output)
