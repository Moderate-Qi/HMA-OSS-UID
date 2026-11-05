package org.frknkrc44.hma_oss.zygote.service

import android.content.pm.ApplicationInfo
import android.os.Process
import android.os.SystemProperties
import android.system.Os
import icu.nullptr.hidemyapplist.common.Utils.binderLocalScope
import icu.nullptr.hidemyapplist.common.Utils.getInstalledApplicationsCompat
import org.frknkrc44.hma_oss.common.BuildConfig
import org.frknkrc44.hma_oss.zygote.util.Logcat.logE
import org.frknkrc44.hma_oss.zygote.util.UserManagerUtils
import org.frknkrc44.hma_oss.zygote.util.ActivityManagerUtils
import java.io.File
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit

/** Publishes bounded, per-caller snapshots. No UID syscall runs in system_server. */
class UidPolicyPublisher(
    private val service: HMAService,
    private val root: File,
    private val executor: ScheduledExecutorService = Executors.newSingleThreadScheduledExecutor { job ->
        Thread(job, "HMA-UidRules").apply { isDaemon = true }
    },
) {
    private val schedulingLock = Any()
    private var requestVersion = 0L
    private var scheduled: ScheduledFuture<*>? = null
    private val retryDelaysMs = longArrayOf(1000, 3000, 10000)
    private val publicationLock = Any()
    @Volatile var status = "PENDING"
        private set
    private val affected = java.util.Collections.synchronizedSet(mutableSetOf<Pair<String, Int>>())
    private val excluded = setOf(BuildConfig.APP_PACKAGE_NAME, "com.sukisu.ultra",
        "me.weishu.kernelsu", "me.bmax.apatch", "com.topjohnwu.magisk")

    fun schedule() = synchronized(schedulingLock) {
        val version = ++requestVersion
        scheduled?.cancel(false)
        status = "PENDING"
        scheduled = executor.schedule(Runnable { publishWhenReady(version, 0) }, 0, TimeUnit.MILLISECONDS)
    }

    private fun defer(version: Long, failures: Int, delayMs: Long, nextStatus: String) =
        synchronized(schedulingLock) {
            if (version == requestVersion) {
                status = nextStatus
                scheduled = executor.schedule(
                    Runnable { publishWhenReady(version, failures) }, delayMs, TimeUnit.MILLISECONDS)
            }
        }

    private fun publishWhenReady(version: Long, failures: Int) {
        if (synchronized(schedulingLock) { version != requestVersion }) return
        val config = service.config
        if (config.uidFilterEnabled && config.uidFilterRevision == 3 &&
            !SystemProperties.getBoolean("sys.boot_completed", false)) {
            // Settings/WebView providers are not available during early system_server startup.
            // Wait on our own worker; never delay a system boot thread or publish a partial list.
            defer(version, failures, 1000, "WAITING_BOOT")
            return
        }
        if (!publish() && failures < retryDelaysMs.size) {
            defer(version, failures + 1, retryDelaysMs[failures],
                "RETRYING ${failures + 1}/${retryDelaysMs.size}: $status")
        }
    }

    fun disableImmediately() = synchronized(publicationLock) {
        root.mkdirs()
        atomicWrite(File(root, "active"), "OFF\n")
        status = "OFF"
    }

    fun restartTargets(): Int {
        val targets = synchronized(affected) { affected.toList() }
        var count = 0
        for ((name, user) in targets) {
            if (name in excluded) continue
            runCatching { binderLocalScope { ActivityManagerUtils.forceStopPackage(name, user) }; count++ }
        }
        return count
    }

    private fun publish(): Boolean {
        try {
            root.mkdirs()
            Os.chmod(root.path, 0x1ed) // 0755, owned by system; no app write access.
            val snapshot = service.config
            if (!snapshot.uidFilterEnabled || snapshot.uidFilterRevision != 3) {
                disableImmediately()
                return true
            }
            val generation = "g${Process.myPid()}_${System.nanoTime()}"
            val directory = File(root, generation).apply { mkdirs() }
            Os.chmod(directory.path, 0x1ed)
            var callers = 0
            binderLocalScope {
                for (user in UserManagerUtils.userIds) {
                    val apps = service.pms.getInstalledApplicationsCompat(0L, user)
                    val byUid = apps.filter { it.uid % 100000 in 10000..19999 }
                        .groupBy { it.uid }
                    for ((uid, group) in byUid) {
                        // A shared UID with a system/critical app is never targeted.
                        if (group.any { it.flags and ApplicationInfo.FLAG_SYSTEM != 0 || it.packageName in excluded }) continue
                        val configured = group.map { it.packageName }.filter { it in snapshot.scope }
                        if (configured.isEmpty()) continue
                        val hidden = byUid.filter { (targetUid, targets) ->
                            targetUid != uid && targets.all { target ->
                                configured.any { caller -> service.shouldHide(caller, target.packageName) }
                            }
                        }.keys.sorted()
                        // Never truncate: partial hiding would silently change the policy.
                        if (hidden.isEmpty() || hidden.size > 128) continue
                        configured.forEach { affected.add(it to user) }
                        atomicWrite(File(directory, uid.toString()),
                            "HMA_UID_3\n${uid}\n" + hidden.joinToString("\n", postfix = "\n"))
                        callers++
                    }
                }
            }
            // Config changes during computation leave the old snapshot active.
            atomicWrite(File(directory, "summary"), "callers=$callers\nversion=${BuildConfig.APP_VERSION_NAME}\n")
            val bootId = File("/proc/sys/kernel/random/boot_id").readText().trim()
            synchronized(publicationLock) {
                if (service.config !== snapshot || (!snapshot.uidFilterEnabled || snapshot.uidFilterRevision != 3)) {
                    schedule()
                    return true
                }
                atomicWrite(File(root, "active"), "$bootId $generation\n")
                status = "READY $callers"
            }
            return true
        } catch (cause: Throwable) {
            // Disable future installations on failure; an old allow/deny list is not substituted.
            runCatching { atomicWrite(File(root, "active"), "OFF\n") }
            status = "ERROR ${cause.javaClass.simpleName}: ${cause.message.orEmpty().lineSequence().firstOrNull().orEmpty().take(160)}"
            logE("UidPolicy", cause) { "UID policy publication failed; new processes stay unchanged" }
            return false
        }
    }

    private fun atomicWrite(file: File, text: String) {
        val next = File(file.parentFile, file.name + ".next")
        next.writeText(text, Charsets.UTF_8)
        Os.chmod(next.path, 0x1a4) // 0644
        Os.rename(next.path, file.path)
    }
}
