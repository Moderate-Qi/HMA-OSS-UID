#include "uid_filter.hpp"
#include <algorithm>
#include <cerrno>
#include <climits>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <dlfcn.h>
#include <dirent.h>
#include <linux/audit.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/system_properties.h>
#include <unistd.h>
#include "uid_policy_budget.hpp"
#include "uid_rule.hpp"
#include "uid_notification.hpp"
#include <android/log.h>

namespace {
bool read_rules(int uid, std::vector<uint32_t>& result) {
    char boot[PROP_VALUE_MAX]{};
    if (__system_property_get("sys.boot_completed", boot) <= 0 || strcmp(boot, "1")) return false;
    char boot_id[48]{};
    FILE* boot_file = fopen("/proc/sys/kernel/random/boot_id", "re");
    if (!boot_file) return false;
    const bool have_boot = fscanf(boot_file, "%47s", boot_id) == 1;
    fclose(boot_file);
    if (!have_boot) return false;
    DIR* directory = opendir("/data/misc");
    if (!directory) return false;
    char path[384]{};
    while (auto* entry = readdir(directory)) {
        if (strncmp(entry->d_name, "hide_my_applist_", 16)) continue;
        snprintf(path, sizeof(path), "/data/misc/%s/uid_scope/active", entry->d_name);
        FILE* active = fopen(path, "re");
        if (!active) continue;
        char generation[96]{};
        char policy_boot[48]{};
        const bool read = fscanf(active, "%47s %95s", policy_boot, generation) == 2 && !strcmp(policy_boot, boot_id);
        fclose(active);
        if (!read || generation[0] != 'g') continue;
        generation[strcspn(generation, "\r\n")] = 0;
        if (strspn(generation, "g0123456789_") != strlen(generation)) continue;
        snprintf(path, sizeof(path), "/data/misc/%s/uid_scope/%s/%d", entry->d_name, generation, uid);
        FILE* file = fopen(path, "re");
        if (!file) continue;
        char magic[32]{};
        unsigned expected = 0, value = 0;
        bool valid = fgets(magic, sizeof(magic), file) && !strcmp(magic, "HMA_UID_3\n") &&
            fscanf(file, "%u", &expected) == 1 && expected == uint32_t(uid);
        while (valid && fscanf(file, "%u", &value) == 1) {
            if (result.size() == 128 || value == uint32_t(uid) || value / 100000 != uint32_t(uid) / 100000 ||
                value % 100000 < 10000 || value % 100000 > 19999) { valid = false; break; }
            result.push_back(value);
        }
        if (ferror(file) || !feof(file)) valid = false;
        fclose(file);
        if (valid && !result.empty()) { closedir(directory); return true; }
        result.clear();
    }
    closedir(directory);
    return false;
}

}

bool HmaUidFilter::prepareCompanion() noexcept {
    if (companion_ >= 0) return true;
    companion_ = api_->connectCompanion();
    if (companion_ < 0) return false;
    if (hma_uid::notification::prepare(companion_, uint32_t(uid_),hidden_)) return true;
    close(companion_); companion_ = -1;
    return false;
}

void HmaUidFilter::prepare(zygisk::Api* api, int uid) noexcept {
    if (uid < 0 || uid % 100000 < 10000 || uid % 100000 > 19999) return;
    if (api->getFlags() & zygisk::PROCESS_GRANTED_ROOT) return;
    try {
        if (!read_rules(uid, hidden_)) return;
        Dl_info info{};
        void* symbol = dlsym(RTLD_DEFAULT, "_Z22set_app_seccomp_filterv");
        if (!symbol || !dladdr(symbol, &info) || !info.dli_fname || stat(info.dli_fname, &runtime_)) return;
        api_ = api; uid_ = uid; current_ = this;
        api_->pltHookRegister(runtime_.st_dev, runtime_.st_ino, "prctl",
            reinterpret_cast<void*>(intercept), reinterpret_cast<void**>(&original_));
        api_->pltHookCommit();
        hooked_ = original_ != nullptr;
        if (!hooked_) current_ = nullptr;
    } catch (...) { /* Allocation/read failures leave Android's own policy in control. */ }
}

int HmaUidFilter::intercept(int option, unsigned long second, unsigned long third,
    unsigned long fourth, unsigned long fifth) {
    HmaUidFilter* self = current_;
    if (!self || !self->original_) { errno = EINVAL; return -1; }
    const int saved_errno = errno;
    if (option == PR_SET_SECCOMP && second == SECCOMP_MODE_FILTER && third && !self->installed_ && !self->specializationDone_) {
        try {
            const auto& original = *reinterpret_cast<const sock_fprog*>(third);
            std::vector<sock_filter> merged;
            if (original.len <= BPF_MAXINSNS &&
                uid_filter::detail::merge_with_budget(original, hma_uid::notification::rule(self->hidden_), merged) &&
                self->prepareCompanion()) {
                const int listener=hma_uid::notification::install(merged);
                if (listener >= 0) {
                    auto delivered=hma_uid::notification::send_listener(self->companion_, listener);
                    if (delivered == hma_uid::notification::Delivery::failed) {
                        // Retry custody with a fresh prepared session. Never
                        // append a static fallback to an installed notifier.
                        close(self->companion_); self->companion_=-1;
                        if (self->prepareCompanion())
                            delivered=hma_uid::notification::send_listener(self->companion_, listener);
                    }
                    close(listener);
                    if(self->companion_>=0){close(self->companion_);self->companion_=-1;}
                    self->installed_ = true;
                    __android_log_print(delivered==hma_uid::notification::Delivery::acknowledged ? ANDROID_LOG_INFO : ANDROID_LOG_WARN,
                        "HMA-UID", "uid=%d mode=notify merged=%zu hidden=%zu handoff=%d", self->uid_, merged.size(), self->hidden_.size(), int(delivered));
                    errno=saved_errno;
                    return 0;
                }
                __android_log_print(ANDROID_LOG_WARN,"HMA-UID","uid=%d unchanged: notification install errno=%d",self->uid_,errno);
            }
            __android_log_print(ANDROID_LOG_WARN, "HMA-UID", "uid=%d unchanged: policy/budget/install unsupported", self->uid_);
        } catch (...) { }
    }
    errno = saved_errno;
    return self->original_(option, second, third, fourth, fifth);
}

bool HmaUidFilter::finish() noexcept {
    specializationDone_=true;
    if(companion_>=0){close(companion_);companion_=-1;}
    if (!hooked_) return true;
    void* displaced = nullptr;
    api_->pltHookRegister(runtime_.st_dev, runtime_.st_ino, "prctl",
        reinterpret_cast<void*>(original_), &displaced);
    const bool committed = api_->pltHookCommit();
    if (!committed || displaced != reinterpret_cast<void*>(intercept)) {
        // A chained callback may still point here. Keep this DSO mapped.
        if (displaced && displaced != reinterpret_cast<void*>(intercept)) {
            void* ignored = nullptr;
            api_->pltHookRegister(runtime_.st_dev, runtime_.st_ino, "prctl", displaced, &ignored);
            api_->pltHookCommit();
        }
        return false;
    }
    hooked_ = false; current_ = nullptr;
    return true;
}
