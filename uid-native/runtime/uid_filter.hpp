#pragma once
#include "ext/zygisk.hpp"
#include <sys/stat.h>
#include <sys/types.h>
#include <vector>
#include <cstdint>
#include <linux/filter.h>

class HmaUidFilter {
    using Prctl = int (*)(int, unsigned long, unsigned long, unsigned long, unsigned long);
    inline static HmaUidFilter* current_ = nullptr;
    zygisk::Api* api_ = nullptr;
    Prctl original_ = nullptr;
    struct stat runtime_{};
    std::vector<uint32_t> hidden_;
    int uid_ = -1;
    bool hooked_ = false;
    bool installed_ = false;
    bool specializationDone_ = false;
    int companion_ = -1;
    bool prepareCompanion() noexcept;
    static int intercept(int, unsigned long, unsigned long, unsigned long, unsigned long);
public:
    void prepare(zygisk::Api*, int uid) noexcept;
    bool finish() noexcept;
};
