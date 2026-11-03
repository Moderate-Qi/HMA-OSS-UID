#pragma once
#include <vector>
#include <cstdint>
#include <cstddef>
#include <cerrno>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/resource.h>
#include <map>

namespace hma_uid {
inline std::vector<sock_filter> make_rule(const std::vector<uint32_t>& uids,
        uint32_t arch=AUDIT_ARCH_AARCH64, uint32_t nr=141,
        uint32_t action=SECCOMP_RET_ERRNO | ESRCH) {
    std::vector<sock_filter> code;
    auto load = [&](uint32_t offset) { code.push_back(BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offset)); };
    auto equal = [&](uint32_t value, uint8_t yes, uint8_t no) { code.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, value, yes, no)); };
    auto ret = [&](uint32_t value) { code.push_back(BPF_STMT(BPF_RET | BPF_K, value)); };
    load(offsetof(seccomp_data, arch)); equal(arch, 1, 0); ret(SECCOMP_RET_ALLOW);
    load(offsetof(seccomp_data, nr)); equal(nr, 1, 0); ret(SECCOMP_RET_ALLOW);
    load(offsetof(seccomp_data, args[0])); equal(PRIO_USER, 1, 0); ret(SECCOMP_RET_ALLOW);
    load(offsetof(seccomp_data, args[1]));
    for (uint32_t uid : uids) { equal(uid, 0, 1); ret(action); }
    ret(SECCOMP_RET_ALLOW);
    // Dense package UIDs are cheaper as exact 32-UID bitmaps. Preserve the
    // identical membership test and choose the smaller cBPF representation.
    std::map<uint32_t, uint32_t> masks;
    for (uint32_t uid : uids) masks[uid >> 5] |= uint32_t{1} << (uid & 31);
    std::vector<sock_filter> bitmap(code.begin(), code.begin() + 9);
    bitmap.push_back(BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, args[1])));
    bitmap.push_back(BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 31));
    bitmap.push_back(BPF_STMT(BPF_MISC | BPF_TAX, 0));
    bitmap.push_back(BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, args[1])));
    bitmap.push_back(BPF_STMT(BPF_ALU | BPF_RSH | BPF_K, 5));
    std::vector<size_t> jumps;
    for (const auto& [bucket, mask] : masks) {
        bitmap.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, bucket, 0, 2));
        bitmap.push_back(BPF_STMT(BPF_LD | BPF_W | BPF_IMM, mask));
        jumps.push_back(bitmap.size());
        bitmap.push_back(BPF_STMT(BPF_JMP | BPF_JA, 0));
    }
    bitmap.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
    const size_t found = bitmap.size();
    for (size_t at : jumps) bitmap[at].k = uint32_t(found - at - 1);
    bitmap.push_back(BPF_STMT(BPF_ALU | BPF_RSH | BPF_X, 0));
    bitmap.push_back(BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, 1, 0, 1));
    bitmap.push_back(BPF_STMT(BPF_RET | BPF_K, action));
    bitmap.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
    return bitmap.size() < code.size() ? bitmap : code;
}
}
