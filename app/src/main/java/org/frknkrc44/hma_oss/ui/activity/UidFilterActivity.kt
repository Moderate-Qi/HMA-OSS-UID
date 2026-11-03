package org.frknkrc44.hma_oss.ui.activity

import android.os.Bundle
import android.view.ViewGroup
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.google.android.material.button.MaterialButton
import com.google.android.material.materialswitch.MaterialSwitch
import icu.nullptr.hidemyapplist.service.ConfigManager
import icu.nullptr.hidemyapplist.service.ServiceClient
import icu.nullptr.hidemyapplist.common.JsonConfig
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.frknkrc44.hma_oss.BuildConfig
import java.io.File
import java.util.concurrent.TimeUnit

/** The manager owns the switch; the matching backend owns policy publication. */
class UidFilterActivity : AppCompatActivity() {
    private lateinit var state: TextView
    private lateinit var toggle: MaterialSwitch
    private lateinit var install: MaterialButton
    private var updating = false
    private fun ready() = ServiceClient.serviceVersionName == BuildConfig.VERSION_NAME

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        title = "UID 过滤（实验）"
        val dp = resources.displayMetrics.density
        val box = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding((24 * dp).toInt(), (36 * dp).toInt(), (24 * dp).toInt(), (24 * dp).toInt())
        }
        fun text(message: String, size: Float = 15f) = TextView(this).apply {
            text = message; textSize = size
            setPadding(0, (10 * dp).toInt(), 0, (10 * dp).toInt())
            box.addView(this, ViewGroup.LayoutParams(-1, -2))
        }
        text("UID 过滤 · v3.1 开机恢复修复", 24f)
        text("按每个应用的 HMA 隐藏规则过滤 UID 查询。仅处理 HMA 作用名单中的普通应用，系统应用、管理器和框架标记为已获 Root 授权的应用保持原状。")
        text("UID 过滤默认开启，更新和重启后会恢复已保存的开关状态。切换会结束已参与过滤的应用，请重新打开它们。手动关闭后新进程恢复原状，无需整机重启。更新后端后需重启手机一次。")
        state = text("正在读取后端状态…")
        toggle = MaterialSwitch(this).apply { text = "启用 UID 过滤"; box.addView(this) }
        install = MaterialButton(this).apply {
            text = "安装／更新集成后端（需要 Root）"
            box.addView(this)
            setOnClickListener { installBackend() }
        }
        MaterialButton(this).apply {
            text = "刷新状态"; box.addView(this)
            setOnClickListener { refresh() }
        }
        text("系统策略不匹配或规则容量不足时，该应用保持原策略，UID 过滤跳过。READY 表示规则已生成；实际装载结果可由 Root 日志中的 HMA-UID 查看。v3 保留 TRACE 兼容，并新增对 getpriority(PRIO_USER) 范围内自建通知监听器的兼容，处理真实描述符、通知收发和等待；更宽的规则保持内核原结果。")
        text("该兼容层仍有可探测边界：虚拟安装的通知策略不会增加目标进程的内核过滤器计数，其容量与转发耗时也可能不同；更深入的探测仍可能发现差异。")
        text("应用使用同步过滤规则或任务跟踪失效时，该会话会暂停 UID 过滤，以保持应用正常运行；重新启动该应用可恢复。日志中的 filtering paused 表示已暂停。")
        MaterialButton(this).apply { text = "返回"; box.addView(this); setOnClickListener { finish() } }
        val scroll = android.widget.ScrollView(this).apply { addView(box) }
        setContentView(scroll)
        toggle.setOnCheckedChangeListener { _, enabled -> if (!updating) change(enabled) }
        refresh()
    }

    private fun refresh() {
        updating = true
        val available = ready()
        toggle.isEnabled = available
        if (available) {
            ConfigManager.init()
            toggle.isChecked = ConfigManager.uidFilterEnabled
            state.text = "后端：${ServiceClient.serviceVersionName}\n规则状态：${ServiceClient.uidFilterStatus}\nWAITING_BOOT 表示等待系统开机完成；RETRYING 表示后台正在重试。"
        } else {
            toggle.isChecked = false
            state.text = "需要与此 APK 配套的集成后端。安装后重启一次，再打开本页。当前后端：${ServiceClient.serviceVersionName ?: "未连接"}"
        }
        updating = false
    }

    private fun change(enabled: Boolean) {
        toggle.isEnabled = false
        lifecycleScope.launch {
            val outcome = withContext(Dispatchers.IO) {
                runCatching {
                    check(ready()) { "后端版本不匹配" }
                    ConfigManager.uidFilterEnabled = enabled
                    check(JsonConfig.parse(ServiceClient.config).let { (it.uidFilterEnabled && it.uidFilterRevision == 3) == enabled }) { "后端未确认开关状态" }
                    var status = "PENDING"
                    for (attempt in 0 until 300) {
                        status = ServiceClient.uidFilterStatus
                        if ((enabled && status.startsWith("READY ")) || (!enabled && status == "OFF") || status.startsWith("ERROR")) break
                        Thread.sleep(100)
                    }
                    check(if (enabled) status.startsWith("READY ") else status == "OFF") { "规则尚未就绪：$status，请刷新后重试" }
                    val stopped = ServiceClient.restartUidFilterTargets()
                    "${if (enabled) "已启用规则" else "已关闭规则"}，已结束 $stopped 个受保护应用。重新打开后生效。\n规则状态：$status"
                }
            }
            refresh()
            state.text = outcome.getOrElse { "操作未完成：${it.message}" }
        }
    }

    private fun installBackend() {
        install.isEnabled = false
        state.text = "正在更新后端；请在 Root 管理器中授权…"
        lifecycleScope.launch {
            val result = withContext(Dispatchers.IO) {
                runCatching {
                    val folder = File(filesDir, "uid-payload").apply { mkdirs() }
                    java.util.zip.ZipInputStream(assets.open("uid-backend.zip")).use { zip ->
                        while (true) {
                            val item = zip.nextEntry ?: break
                            require(!item.name.contains("..") && !item.name.startsWith("/"))
                            val target = File(folder, item.name)
                            if (item.isDirectory) target.mkdirs() else {
                                target.parentFile?.mkdirs()
                                target.outputStream().use { zip.copyTo(it) }
                            }
                        }
                    }
                    val command = "sh '${File(folder, "install-backend.sh").absolutePath}' '${folder.absolutePath}'"
                    val process = ProcessBuilder("su", "-c", command).redirectErrorStream(true).start()
                    val output = StringBuilder()
                    val reader = Thread { process.inputStream.bufferedReader().useLines { lines ->
                        lines.forEach { if (output.length < 16000) output.append(it).append('\n') }
                    } }.apply { isDaemon = true; start() }
                    if (!process.waitFor(120, TimeUnit.SECONDS)) { process.destroy(); error("Root 操作超时，请查看模块状态") }
                    reader.join(1000)
                    check(process.exitValue() == 0) { output.toString() }
                    output.toString()
                }
            }
            install.isEnabled = true
            state.text = result.getOrElse { "更新未完成：${it.message}" }
        }
    }
}
