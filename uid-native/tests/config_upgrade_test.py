"""Exercise the built configuration serializer across the upstream 93 -> 94 change.

Fixtures remain on disk. Set JAVA_HOME and ANDROID_HOME to the build toolchain.
"""
from pathlib import Path
import os
import subprocess
import time

source = Path(__file__).resolve().parents[2]
fixture = source.parent / 'evidence' / ('config-upgrade-' + str(time.time_ns()))
fixture.mkdir(parents=True)
cache = Path.home() / '.gradle/caches/modules-2/files-2.1'
dependencies = [source / 'common/build/intermediates/compile_library_classes_jar/release/bundleLibCompileToJarRelease/classes.jar']
for relative in ['org.jetbrains.kotlin/kotlin-stdlib/2.4.21',
                 'org.jetbrains.kotlinx/kotlinx-serialization-json-jvm/1.11.0',
                 'org.jetbrains.kotlinx/kotlinx-serialization-core-jvm/1.11.0']:
    dependencies.append(next((cache / relative).rglob('*.jar')))
dependencies.append(Path(os.environ['ANDROID_HOME']) / 'platforms/android-37.0/android.jar')
java = Path(os.environ['JAVA_HOME']) / 'bin'
suffix = '.exe' if os.name == 'nt' else ''
test = fixture / 'ConfigUpgradeTest.java'
test.write_text('''import icu.nullptr.hidemyapplist.common.JsonConfig;
public class ConfigUpgradeTest {
    static void verify(boolean ok, String label) {
        if (!ok) throw new AssertionError(label);
        System.out.println("PASS " + label);
    }
    public static void main(String[] args) {
        JsonConfig fresh = new JsonConfig();
        verify(fresh.getConfigVersion() == 94, "upstream configuration version 94");
        verify(fresh.getUidFilterEnabled() && fresh.getUidFilterRevision() == 3,
               "fresh configuration defaults ON revision 3");
        JsonConfig missing = JsonConfig.Companion.parse("{}");
        verify(missing.getUidFilterEnabled(), "legacy missing UID fields defaults ON");
        String previous = "{\\"configVersion\\":93,\\"webViewProtection\\":true,"
            + "\\"ignoreBrandProtections\\":false,\\"uidFilterEnabled\\":true,\\"uidFilterRevision\\":3,"
            + "\\"scope\\":{\\"example.target\\":{\\"extraAppList\\":[\\"example.hidden\\"]}}}";
        JsonConfig migrated = JsonConfig.Companion.parse(previous);
        migrated.setConfigVersion(94);
        JsonConfig saved = JsonConfig.Companion.parse(migrated.toString());
        verify(saved.getUidFilterEnabled() && saved.getUidFilterRevision() == 3,
               "ON survives old fields removal and save/reload");
        verify(saved.getScope().get("example.target").getExtraAppList().contains("example.hidden"),
               "target and hidden package rules survive upgrade");
        verify(!saved.toString().contains("webViewProtection")
            && !saved.toString().contains("ignoreBrandProtections"), "retired upstream fields removed");
        JsonConfig off = JsonConfig.Companion.parse(previous.replace("\\"uidFilterEnabled\\":true",
                                                                  "\\"uidFilterEnabled\\":false"));
        off.setConfigVersion(94);
        verify(!JsonConfig.Companion.parse(off.toString()).getUidFilterEnabled(),
               "explicit manual OFF survives upgrade and save/reload");
    }
}
''', encoding='utf-8')
classpath = os.pathsep.join(map(str, dependencies))
subprocess.run([str(java / ('javac' + suffix)), '-cp', classpath, '-d', str(fixture), str(test)], check=True)
subprocess.run([str(java / ('java' + suffix)), '-cp', str(fixture) + os.pathsep + classpath, 'ConfigUpgradeTest'], check=True)
print('Fixture retained:', fixture)
