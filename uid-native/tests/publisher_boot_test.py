"""Execute the production Kotlin publisher with Android service stubs and a manual clock.

Only /proc/boot_id is remapped to a host fixture; publisher logic is compiled unchanged.
Every generated fixture/build artifact is retained. No phone access or cleanup.
"""
from pathlib import Path
import os
import subprocess
import time

source = Path(__file__).resolve().parents[2]
root = source.parent
fixture = root / 'evidence' / ('publisher-boot-' + str(time.time_ns()))
fixture.mkdir(parents=True)
boot = fixture / 'boot_id'
boot.write_text('boot-current\n', encoding='utf-8')
publisher = source / 'zygote/src/main/java/org/frknkrc44/hma_oss/zygote/service/UidPolicyPublisher.kt'
host_source = publisher.read_text(encoding='utf-8').replace(
    'File("/proc/sys/kernel/random/boot_id")', 'File("' + boot.as_posix() + '")')
(fixture / 'UidPolicyPublisher.kt').write_text(host_source, encoding='utf-8')
stubs = {
    'AppInfo.kt': '''package android.content.pm
class ApplicationInfo(val uid: Int, val packageName: String, val flags: Int = 0) {
    companion object { const val FLAG_SYSTEM = 1 }
}
''',
    'AndroidOs.kt': '''package android.os
object Process { fun myPid() = 123 }
object SystemProperties {
    var boot = false
    fun getBoolean(key: String, fallback: Boolean): Boolean {
        check(key == "sys.boot_completed"); return boot
    }
}
''',
    'Os.kt': '''package android.system
import java.nio.file.*
object Os {
    fun chmod(path: String, mode: Int) { check(Files.exists(Path.of(path))) }
    fun rename(from: String, to: String) {
        Files.move(Path.of(from), Path.of(to), StandardCopyOption.REPLACE_EXISTING)
    }
}
''',
    'BuildConfig.kt': '''package org.frknkrc44.hma_oss.common
object BuildConfig {
    const val APP_PACKAGE_NAME = "org.frknkrc44.hma_oss"
    const val APP_VERSION_NAME = "boot-test"
}
''',
    'Utils.kt': '''package icu.nullptr.hidemyapplist.common
import org.frknkrc44.hma_oss.zygote.service.Pms
object Utils {
    fun <T> binderLocalScope(block: () -> T): T = block()
    fun Pms.getInstalledApplicationsCompat(flags: Long, user: Int) = apps.also { calls++ }
}
''',
    'Service.kt': '''package org.frknkrc44.hma_oss.zygote.service
import android.content.pm.ApplicationInfo
class Config(var uidFilterEnabled: Boolean = true, var uidFilterRevision: Int = 3) {
    val scope = setOf("caller")
}
class Pms {
    var calls = 0
    val apps = listOf(ApplicationInfo(10050, "caller"), ApplicationInfo(10051, "hidden"))
}
class HMAService {
    var config = Config()
    val pms = Pms()
    var providerReady = false
    var onQuery: (() -> Unit)? = null
    fun shouldHide(caller: String, target: String, user: Int): Boolean {
        onQuery?.invoke()
        check(providerReady) { "Cannot access system provider: 'settings' before system providers are installed!" }
        return target == "hidden"
    }
}
''',
    'Utility.kt': '''package org.frknkrc44.hma_oss.zygote.util
object UserManagerUtils { val userIds = intArrayOf(0) }
object ActivityManagerUtils { fun forceStopPackage(name: String, user: Int) {} }
object Logcat {
    var failures = 0
    fun logE(tag: String, cause: Throwable, message: () -> String) { failures++ }
}
''',
    'Main.kt': '''import org.frknkrc44.hma_oss.zygote.service.*
import org.frknkrc44.hma_oss.zygote.util.Logcat
import android.os.SystemProperties
import java.io.File
import java.util.concurrent.*

class Manual : ScheduledThreadPoolExecutor(1) {
    var now = 0L
    val jobs = mutableListOf<Work>()
    class Work(run: Runnable, val due: Long) : FutureTask<Unit>(run, Unit), ScheduledFuture<Unit> {
        override fun getDelay(unit: TimeUnit) = unit.convert(due, TimeUnit.MILLISECONDS)
        override fun compareTo(other: Delayed) = due.compareTo((other as Work).due)
    }
    override fun schedule(command: Runnable, delay: Long, unit: TimeUnit): ScheduledFuture<*> =
        Work(command, now + unit.toMillis(delay)).also { jobs.add(it) }
    fun step() {
        val job = jobs.minBy { it.due }; jobs.remove(job); now = job.due
        job.run(); if (!job.isCancelled) job.get()
    }
    fun drain() {
        var count = 0
        while (jobs.isNotEmpty()) { check(++count < 20); step() }
    }
}
fun main(args: Array<String>) {
    val base = File(args.single())
    fun scenario(name: String, enabled: Boolean = true, run: (HMAService, Manual, UidPolicyPublisher, File) -> Unit) {
        SystemProperties.boot = false
        val service = HMAService().also { it.config.uidFilterEnabled = enabled }
        val clock = Manual()
        val dir = File(base, name)
        val publisher = UidPolicyPublisher(service, dir, clock)
        run(service, clock, publisher, dir)
        println("PASS $name")
    }
    scenario("saved-on-waits-and-recovers") { s, c, p, dir ->
        p.schedule(); c.step()
        check(p.status == "WAITING_BOOT" && s.pms.calls == 0)
        repeat(3) { c.step(); check(s.pms.calls == 0) }
        SystemProperties.boot = true; s.providerReady = true; c.drain()
        check(p.status == "READY 1" && s.config.uidFilterEnabled)
        val active = File(dir, "active").readText().trim().split(' ')
        check(active[0] == "boot-current")
        check(File(dir, active[1] + "/10050").readText() == "HMA_UID_3\\n10050\\n10051\\n")
    }
    scenario("saved-off-never-waits", false) { s, c, p, dir ->
        p.schedule(); c.drain()
        check(p.status == "OFF" && s.pms.calls == 0 && !s.config.uidFilterEnabled)
        check(File(dir, "active").readText() == "OFF\\n")
    }
    scenario("disable-during-boot-cancels-recovery") { s, c, p, dir ->
        p.schedule(); c.step(); s.config = Config(false)
        p.disableImmediately(); p.schedule(); c.drain()
        SystemProperties.boot = true; c.drain()
        check(p.status == "OFF" && s.pms.calls == 0)
        check(File(dir, "active").readText() == "OFF\\n")
    }
    scenario("late-settings-provider-retries") { s, c, p, _ ->
        SystemProperties.boot = true
        p.schedule(); c.step()
        check(p.status.startsWith("RETRYING 1/3: ERROR IllegalStateException:"))
        check(s.config.uidFilterEnabled)
        s.providerReady = true; c.drain(); check(p.status == "READY 1")
    }
    scenario("persistent-error-bounded-and-explained") { s, c, p, _ ->
        SystemProperties.boot = true
        p.schedule(); val initialFailures = Logcat.failures; c.drain()
        check(Logcat.failures - initialFailures == 4)
        check(p.status.startsWith("ERROR IllegalStateException: Cannot access system provider"))
        check(s.config.uidFilterEnabled && c.now == 14000L)
        s.providerReady = true; p.schedule(); c.drain(); check(p.status == "READY 1")
    }
    scenario("config-change-during-publication") { s, c, p, dir ->
        SystemProperties.boot = true; s.providerReady = true
        s.onQuery = { s.onQuery = null; s.config = Config(false); p.schedule() }
        p.schedule(); c.drain()
        check(p.status == "OFF" && File(dir, "active").readText() == "OFF\\n")
    }
    println("PASS 6 publisher boot/state recovery scenarios; Android services are stubbed, clock is manual.")
}
''',
}
for name, text in stubs.items():
    (fixture / name).write_text(text, encoding='utf-8')
cache = Path.home() / '.gradle/caches/modules-2/files-2.1'
compiler = next((cache / 'org.jetbrains.kotlin/kotlin-compiler-embeddable/2.4.21').rglob('*.jar'))
stdlib = next((cache / 'org.jetbrains.kotlin/kotlin-stdlib/2.4.21').rglob('*.jar'))
dependencies = [compiler, stdlib]
for relative in ['org.jetbrains.kotlin/kotlin-script-runtime/2.4.21', 'org.jetbrains.kotlin/kotlin-reflect/1.6.10',
                 'org.jetbrains/annotations', 'org.jetbrains.kotlinx/kotlinx-coroutines-core-jvm']:
    candidates = list((cache / relative).rglob('*.jar'))
    if candidates:
        dependencies.append(candidates[-1])
java = root.parent.parent / 'XHS_Downloader_Android/jdk-21/jdk-21.0.12.1+1/bin/java.exe'
if not java.exists():
    java = Path(os.environ['JAVA_HOME']) / 'bin/java.exe'
output = fixture / 'classes'
subprocess.run([str(java), '-cp', os.pathsep.join(map(str, dependencies)),
    'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler', '-no-stdlib', '-no-reflect',
    '-classpath', str(stdlib), '-d', str(output), *map(str, fixture.glob('*.kt'))], check=True)
subprocess.run([str(java), '-cp', os.pathsep.join(map(str, [output, stdlib])), 'MainKt', str(fixture)], check=True)
print('Fixture retained:', fixture)
